"""
Application Layer - Services/Use Cases
Clean Architecture: Application Layer
Business logic for forensic diagnosis
"""
import json
import re
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta

from src.domain.entities import (
    ProcessInfo,
    DockerContainerState,
    DockerHealthState,
    ResourceLeakInfo,
    ConnectionStateCount,
    KernelMessage,
    KernelBufferResult,
    BackgroundTask,
    ConnectionRateInfo,
    BruteForceAttempt,
    PortScanEvent,
    SecurityLogEvent,
    AnomalyEvent,
    NetworkConnection,
    MalwareIndicator,
    SecurityThreat,
    AttackSeverity,
    ScanPattern,
    AnomalyType,
    MalwareType,
)
from src.domain.interfaces import ISystemExecutor

logger = logging.getLogger(__name__)


class ProcessAnalyzer:
    """
    Service for system process analysis.
    Detects Zombie (Z) and Uninterruptible Sleep (D) processes.
    """
    
    # Command: ps -eo pid,ppid,stat,%cpu,%mem,etime,cmd
    # Displays: PID, Parent PID, Status, CPU%, MEM%, Elapsed Time, Command
    PS_COMMAND = "ps -eo pid,ppid,stat,%cpu,%mem,etime,cmd --no-headers"
    
    def __init__(self, executor: ISystemExecutor):
        self.executor = executor
    
    def scan_anomalies(self) -> Dict[str, Any]:
        """
        Scan all processes and identify anomalies.
        
        Returns:
            Dictionary with all processes and flagged anomalies
        """
        stdout, stderr, code = self.executor.execute_with_shell(self.PS_COMMAND)
        
        if code != 0:
            return {
                "success": False,
                "error": stderr or "Failed to execute ps command",
                "processes": [],
                "anomalies": []
            }
        
        processes: List[ProcessInfo] = []
        anomalies: List[ProcessInfo] = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                # Parse ps output
                parts = line.split(None, 6)  # Split max 7 parts
                if len(parts) < 7:
                    continue
                
                proc = ProcessInfo(
                    pid=int(parts[0]),
                    ppid=int(parts[1]),
                    stat=parts[2],
                    cpu_percent=float(parts[3]),
                    mem_percent=float(parts[4]),
                    elapsed_time=parts[5],
                    command=parts[6]
                )
                processes.append(proc)
                
                if proc.is_anomaly:
                    anomalies.append(proc)
                    
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse line: {line} - {e}")
                continue
        
        return {
            "success": True,
            "total_processes": len(processes),
            "anomaly_count": len(anomalies),
            "zombies": [self._proc_to_dict(p) for p in anomalies if p.is_zombie],
            "disk_sleep": [self._proc_to_dict(p) for p in anomalies if p.is_disk_sleep],
            "all_processes": [self._proc_to_dict(p) for p in processes[:100]]  # Limit output
        }
    
    def _proc_to_dict(self, proc: ProcessInfo) -> Dict:
        return {
            "pid": proc.pid,
            "ppid": proc.ppid,
            "stat": proc.stat,
            "cpu": proc.cpu_percent,
            "mem": proc.mem_percent,
            "elapsed": proc.elapsed_time,
            "command": proc.command[:100],  # Truncate long commands
            "is_zombie": proc.is_zombie,
            "is_disk_sleep": proc.is_disk_sleep
        }


class DockerInspector:
    """
    Service for deep inspection of Docker containers.
    Extracts OOMKilled, ExitCode, RestartCount, Health, Storage.
    """
    
    def __init__(self, executor: ISystemExecutor):
        self.executor = executor
    
    def inspect_container(self, container_name: str) -> Dict[str, Any]:
        """
        Deep inspect a container.
        
        Args:
            container_name: Container name or ID
            
        Returns:
            Dictionary with container state
        """
        if not self.executor.is_command_available("docker"):
            return {
                "success": False,
                "error": "Docker command not available"
            }
        
        # docker inspect <container>
        stdout, stderr, code = self.executor.execute(f"docker inspect {container_name}")
        
        if code != 0:
            return {
                "success": False,
                "error": stderr or f"Failed to inspect container: {container_name}"
            }
        
        try:
            data = json.loads(stdout)
            if not data:
                return {"success": False, "error": "Container not found"}
            
            container = data[0]
            state = container.get("State", {})
            
            # Extract health info if available
            health = None
            if "Health" in state:
                h = state["Health"]
                health = DockerHealthState(
                    status=h.get("Status", ""),
                    failing_streak=h.get("FailingStreak", 0),
                    log=[entry.get("Output", "")[:200] for entry in h.get("Log", [])[-3:]]
                )
            
            # Extract storage info
            graph_driver = container.get("GraphDriver", {})
            storage_data = graph_driver.get("Data", {})
            
            result = DockerContainerState(
                container_name=container.get("Name", "").lstrip("/"),
                container_id=container.get("Id", "")[:12],
                status=state.get("Status", ""),
                running=state.get("Running", False),
                oom_killed=state.get("OOMKilled", False),
                exit_code=state.get("ExitCode", 0),
                restart_count=container.get("RestartCount", 0),
                health=health,
                storage_driver=graph_driver.get("Name", ""),
                storage_data=storage_data
            )
            
            return {
                "success": True,
                "container": {
                    "name": result.container_name,
                    "id": result.container_id,
                    "status": result.status,
                    "running": result.running,
                    "oom_killed": result.oom_killed,
                    "exit_code": result.exit_code,
                    "restart_count": result.restart_count,
                    "health": {
                        "status": result.health.status,
                        "failing_streak": result.health.failing_streak,
                        "recent_logs": result.health.log
                    } if result.health else None,
                    "storage": {
                        "driver": result.storage_driver,
                        "upper_dir": storage_data.get("UpperDir", ""),
                        "work_dir": storage_data.get("WorkDir", "")
                    }
                },
                "warnings": self._generate_warnings(result)
            }
            
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse docker output: {e}"}
    
    def _generate_warnings(self, state: DockerContainerState) -> List[str]:
        """Generate warning messages based on container state"""
        warnings = []
        
        if state.oom_killed:
            warnings.append("⚠️ CRITICAL: Container was killed by OOM Killer!")
        
        if state.exit_code != 0 and not state.running:
            warnings.append(f"⚠️ Container exited with non-zero code: {state.exit_code}")
        
        if state.restart_count > 5:
            warnings.append(f"⚠️ High restart count: {state.restart_count} restarts")
        
        if state.health and state.health.status == "unhealthy":
            warnings.append(f"⚠️ Container health check failing: {state.health.failing_streak} failures")
        
        return warnings


class ResourceLeakDetector:
    """
    Service for detecting resource leaks.
    - File descriptor exhaustion
    - Network connection leaks (CLOSE_WAIT, TIME_WAIT)
    """
    
    # Commands
    LSOF_COUNT_CMD = "lsof 2>/dev/null | wc -l"
    ULIMIT_CMD = "ulimit -n"
    NETSTAT_CMD = "netstat -tan 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -rn"
    # Alternative using ss if netstat not available
    SS_CMD = "ss -tan 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn"
    
    # Thresholds
    CLOSE_WAIT_THRESHOLD = 100
    TIME_WAIT_THRESHOLD = 500
    
    def __init__(self, executor: ISystemExecutor):
        self.executor = executor
    
    def check_leaks(self) -> Dict[str, Any]:
        """
        Check for file descriptor and connection leaks.
        
        Returns:
            Dictionary with resource leak information
        """
        result = {
            "success": True,
            "file_descriptors": self._check_fd_leaks(),
            "connections": self._check_connection_leaks(),
            "warnings": []
        }
        
        # Generate warnings
        fd_info = result["file_descriptors"]
        if fd_info.get("usage_percent", 0) > 80:
            result["warnings"].append(
                f"⚠️ High FD usage: {fd_info['usage_percent']:.1f}% "
                f"({fd_info['open_count']}/{fd_info['limit']})"
            )
        
        for conn in result["connections"].get("states", []):
            if conn["state"] == "CLOSE_WAIT" and conn["count"] > self.CLOSE_WAIT_THRESHOLD:
                result["warnings"].append(
                    f"⚠️ High CLOSE_WAIT connections: {conn['count']} "
                    "(possible connection leak)"
                )
            if conn["state"] == "TIME_WAIT" and conn["count"] > self.TIME_WAIT_THRESHOLD:
                result["warnings"].append(
                    f"⚠️ High TIME_WAIT connections: {conn['count']} "
                    "(high connection churn)"
                )
        
        return result
    
    def _check_fd_leaks(self) -> Dict[str, Any]:
        """Check file descriptor usage"""
        # Get open files count
        stdout, _, code = self.executor.execute_with_shell(self.LSOF_COUNT_CMD)
        open_count = int(stdout.strip()) if code == 0 and stdout.strip().isdigit() else 0
        
        # Get ulimit
        stdout, _, code = self.executor.execute_with_shell(self.ULIMIT_CMD)
        limit = int(stdout.strip()) if code == 0 and stdout.strip().isdigit() else 1024
        
        usage_percent = (open_count / limit * 100) if limit > 0 else 0
        
        return {
            "open_count": open_count,
            "limit": limit,
            "usage_percent": round(usage_percent, 2),
            "is_critical": usage_percent > 80
        }
    
    def _check_connection_leaks(self) -> Dict[str, Any]:
        """Check network connection states"""
        # Try netstat first, fallback to ss
        if self.executor.is_command_available("netstat"):
            stdout, _, code = self.executor.execute_with_shell(self.NETSTAT_CMD)
        else:
            stdout, _, code = self.executor.execute_with_shell(self.SS_CMD)
        
        states: List[Dict] = []
        
        if code == 0 and stdout.strip():
            for line in stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        count = int(parts[0])
                        state = parts[1]
                        
                        # Skip header-like entries
                        if state in ('State', 'Foreign'):
                            continue
                        
                        is_warning = (
                            (state == "CLOSE_WAIT" and count > self.CLOSE_WAIT_THRESHOLD) or
                            (state == "TIME_WAIT" and count > self.TIME_WAIT_THRESHOLD)
                        )
                        
                        states.append({
                            "state": state,
                            "count": count,
                            "is_warning": is_warning
                        })
                    except ValueError:
                        continue
        
        return {"states": states}


class KernelBufferReader:
    """
    Service for reading kernel ring buffer (dmesg).
    Detects OOM, segfault, killed processes.
    """
    
    DMESG_CMD = "dmesg --time-format=reltime 2>/dev/null | tail -n 100"
    DMESG_FALLBACK = "dmesg | tail -n 100"
    
    # Keywords to search for
    CRITICAL_KEYWORDS = [
        "out of memory",
        "oom",
        "segfault",
        "kill process",
        "killed",
        "general protection fault",
        "kernel panic"
    ]
    
    def __init__(self, executor: ISystemExecutor):
        self.executor = executor
    
    def read_buffer(self, lines: int = 50) -> Dict[str, Any]:
        """
        Read and analyze kernel ring buffer.
        
        Args:
            lines: Number of lines to read
            
        Returns:
            Dictionary with messages and critical events
        """
        # Try with time format first
        cmd = f"dmesg --time-format=reltime 2>/dev/null | tail -n {lines}"
        stdout, stderr, code = self.executor.execute_with_shell(cmd)
        
        # Fallback if time-format not supported
        if code != 0 or not stdout.strip():
            cmd = f"dmesg 2>/dev/null | tail -n {lines}"
            stdout, stderr, code = self.executor.execute_with_shell(cmd)
        
        if code != 0:
            # May need sudo for dmesg
            return {
                "success": False,
                "error": stderr or "Failed to read dmesg (may need sudo)",
                "messages": [],
                "critical_events": []
            }
        
        messages: List[KernelMessage] = []
        critical_events: List[Dict] = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            msg = KernelMessage(raw_line=line)
            messages.append(msg)
            
            if msg.is_critical:
                event = {
                    "message": line[:200],
                    "type": []
                }
                if msg.has_oom:
                    event["type"].append("OOM")
                if msg.has_segfault:
                    event["type"].append("SEGFAULT")
                if msg.has_kill:
                    event["type"].append("KILL")
                critical_events.append(event)
        
        result = KernelBufferResult(
            messages=messages,
            critical_count=len(critical_events),
            oom_events=sum(1 for m in messages if m.has_oom),
            segfault_events=sum(1 for m in messages if m.has_segfault),
            kill_events=sum(1 for m in messages if m.has_kill)
        )
        
        return {
            "success": True,
            "total_lines": len(messages),
            "critical_count": result.critical_count,
            "summary": {
                "oom_events": result.oom_events,
                "segfault_events": result.segfault_events,
                "kill_events": result.kill_events
            },
            "critical_events": critical_events,
            "recent_messages": [m.raw_line for m in messages[-20:]]
        }


class BackgroundTaskAnalyzer:
    """
    Service for analyzing background tasks.
    Finds non-root processes consuming CPU/Memory.
    """
    
    # ps command for background processes (excluding root)
    PS_CMD = "ps -eo user,pid,%cpu,%mem,cmd --no-headers | grep -v '^root' | sort -k3 -rn"
    
    def __init__(self, executor: ISystemExecutor):
        self.executor = executor
    
    def analyze(self, min_cpu: float = 0.0, min_mem: float = 0.0) -> Dict[str, Any]:
        """
        Analyze background tasks consuming resources.
        
        Args:
            min_cpu: Minimum CPU% to include
            min_mem: Minimum MEM% to include
            
        Returns:
            Dictionary with list of background tasks
        """
        stdout, stderr, code = self.executor.execute_with_shell(self.PS_CMD)
        
        if code != 0:
            return {
                "success": False,
                "error": stderr or "Failed to list processes",
                "tasks": []
            }
        
        tasks: List[BackgroundTask] = []
        resource_hogs: List[BackgroundTask] = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                parts = line.split(None, 4)
                if len(parts) < 5:
                    continue
                
                cpu = float(parts[2])
                mem = float(parts[3])
                
                # Filter based on min thresholds
                if cpu < min_cpu and mem < min_mem:
                    continue
                
                task = BackgroundTask(
                    pid=int(parts[1]),
                    user=parts[0],
                    cpu_percent=cpu,
                    mem_percent=mem,
                    command=parts[4]
                )
                tasks.append(task)
                
                if task.is_resource_hog:
                    resource_hogs.append(task)
                    
            except (ValueError, IndexError):
                continue
        
        return {
            "success": True,
            "total_tasks": len(tasks),
            "resource_hogs_count": len(resource_hogs),
            "resource_hogs": [
                {
                    "pid": t.pid,
                    "user": t.user,
                    "cpu": t.cpu_percent,
                    "mem": t.mem_percent,
                    "command": t.command[:100]
                }
                for t in resource_hogs
            ],
            "all_tasks": [
                {
                    "pid": t.pid,
                    "user": t.user,
                    "cpu": t.cpu_percent,
                    "mem": t.mem_percent,
                    "command": t.command[:100]
                }
                for t in tasks[:50]  # Limit output
            ]
        }


# ============================================================================
# SECURITY DETECTION SERVICES
# ============================================================================

class DDoSDetector:
    """
    Service for detecting DDoS (Distributed Denial of Service) attacks.
    - SYN flood detection (connections in SYN_RECV state)
    - Connection rate analysis per IP
    - High connection count detection
    """

    # Commands for network connection analysis
    NETSTAT_CMD = "netstat -nt 2>/dev/null"
    SS_CMD = "ss -nt 2>/dev/null"
    SS_DETAIL_CMD = "ss -nt state syn-recv 2>/dev/null"

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def detect_attack(self) -> Dict[str, Any]:
        """
        Detect DDoS attack patterns.

        Returns:
            Dictionary with attack detection results
        """
        import config

        # Get network connections
        connections = self._get_connections()

        if not connections:
            return {
                "success": True,
                "threats_found": 0,
                "threats": [],
                "warnings": ["No connection data available"],
                "data": {
                    "connection_analysis": {},
                    "top_sources": []
                },
                "recommendations": []
            }

        # Analyze connections by IP
        ip_stats = self._analyze_by_ip(connections)

        # Detect SYN flood
        syn_floods = self._detect_syn_flood(connections)

        # Build threat list
        threats = []
        for ip, stats in ip_stats.items():
            if stats["total"] >= config.DDOS_CONN_THRESHOLD:
                threat = SecurityThreat(
                    threat_type="ddos_high_connection_rate",
                    severity=AttackSeverity.HIGH if stats["total"] < config.DDOS_CONN_THRESHOLD * 2 else AttackSeverity.CRITICAL,
                    source_ip=ip,
                    description=f"High connection rate from {ip}: {stats['total']} connections",
                    timestamp=datetime.now().isoformat(),
                    details={
                        "connection_count": stats["total"],
                        "connections_per_second": round(stats["total"] / config.DDOS_TIME_WINDOW, 2),
                        "syn_recv_count": stats.get("syn_recv", 0),
                        "ports": stats.get("ports", [])
                    },
                    recommendations=[
                        f"Block IP {ip} using firewall",
                        "Implement rate limiting",
                        "Consider using DDoS protection service"
                    ]
                )
                threats.append(threat.to_dict())

        # Add SYN flood threats
        for syn_info in syn_floods:
            threat = SecurityThreat(
                threat_type="ddos_syn_flood",
                severity=AttackSeverity.CRITICAL,
                source_ip=syn_info["ip"],
                description=f"SYN flood attack detected from {syn_info['ip']}: {syn_info['syn_count']} SYN_RECV connections",
                timestamp=datetime.now().isoformat(),
                details=syn_info,
                recommendations=[
                    f"Immediately block IP {syn_info['ip']}",
                    "Enable SYN cookies",
                    "Increase backlog queue"
                ]
            )
            threats.append(threat.to_dict())

        # Get top sources
        top_sources = sorted(
            [{"ip": ip, **stats} for ip, stats in ip_stats.items()],
            key=lambda x: x["total"],
            reverse=True
        )[:10]

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": [f"High connection count from {t['source_ip']}" for t in threats],
            "data": {
                "total_connections": len(connections),
                "unique_ips": len(ip_stats),
                "syn_recv_total": sum(1 for c in connections if c.get("state") == "SYN_RECV"),
                "top_sources": top_sources
            },
            "recommendations": [
                "Monitor connection rates regularly",
                "Set up automated IP blocking",
                "Consider rate limiting per IP"
            ] if not threats else []
        }

    def _get_connections(self) -> List[Dict]:
        """Get network connections using netstat or ss"""
        connections = []

        # Try netstat first
        cmd = self.NETSTAT_CMD
        stdout, _, code = self.executor.execute_with_shell(cmd)

        # Fallback to ss
        if code != 0 or not stdout.strip():
            cmd = self.SS_CMD
            stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0 or not stdout.strip():
            return connections

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith("Proto") or line.startswith("State"):
                continue

            # Parse netstat output
            parts = line.split()
            if len(parts) < 6:
                continue

            try:
                conn = {
                    "proto": parts[0],
                    "local_addr": parts[3],
                    "remote_addr": parts[4] if len(parts) > 4 else "",
                    "state": parts[5] if len(parts) > 5 else ""
                }

                # Extract IP from remote address
                if ":" in conn["remote_addr"]:
                    remote_ip = conn["remote_addr"].rsplit(":", 1)[0]
                    remote_port = int(conn["remote_addr"].rsplit(":", 1)[1])
                    conn["remote_ip"] = remote_ip
                    conn["remote_port"] = remote_port

                connections.append(conn)
            except (ValueError, IndexError):
                continue

        return connections

    def _analyze_by_ip(self, connections: List[Dict]) -> Dict[str, Dict]:
        """Analyze connections grouped by source IP"""
        ip_stats = {}

        for conn in connections:
            ip = conn.get("remote_ip", "")
            if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                continue

            if ip not in ip_stats:
                ip_stats[ip] = {"total": 0, "syn_recv": 0, "ports": set()}

            ip_stats[ip]["total"] += 1

            if conn.get("state") == "SYN_RECV":
                ip_stats[ip]["syn_recv"] += 1

            port = conn.get("remote_port")
            if port:
                ip_stats[ip]["ports"].add(port)

        # Convert sets to lists
        for ip in ip_stats:
            ip_stats[ip]["ports"] = list(ip_stats[ip]["ports"])

        return ip_stats

    def _detect_syn_flood(self, connections: List[Dict]) -> List[Dict]:
        """Detect SYN flood patterns"""
        import config

        syn_recv_by_ip = {}
        for conn in connections:
            if conn.get("state") == "SYN_RECV":
                ip = conn.get("remote_ip", "")
                if ip:
                    syn_recv_by_ip[ip] = syn_recv_by_ip.get(ip, 0) + 1

        floods = []
        for ip, count in syn_recv_by_ip.items():
            if count >= config.DDOS_CONN_THRESHOLD * config.DDOS_SYN_FLOOD_RATIO:
                floods.append({
                    "ip": ip,
                    "syn_count": count,
                    "ratio": round(count / max(len(connections), 1), 2)
                })

        return floods


class BruteForceDetector:
    """
    Service for detecting brute force attacks.
    - Monitors auth.log / secure.log for failed SSH/FTP logins
    - Tracks repeated attempts from same IP
    - Detects invalid username patterns
    """

    # Commands for log analysis
    AUTH_LOG_CMD = "tail -n 1000 /var/log/auth.log 2>/dev/null"
    SECURE_LOG_CMD = "tail -n 1000 /var/log/secure 2>/dev/null"
    JOURNALCTL_CMD = "journalctl -u ssh -n 1000 --no-pager 2>/dev/null"

    # Patterns for detecting brute force
    FAILED_PASSWORD_PATTERN = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*?Failed password for (?:invalid user )?(\S+) from (\S+)'
    )
    INVALID_USER_PATTERN = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*?Invalid user (\S+) from (\S+)'
    )
    ACCEPTED_PASSWORD_PATTERN = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*?Accepted password for (\S+) from (\S+)'
    )

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def detect_attack(self) -> Dict[str, Any]:
        """
        Detect brute force attack patterns.

        Returns:
            Dictionary with attack detection results
        """
        import config

        # Get auth logs
        log_lines = self._get_auth_logs()

        if not log_lines:
            return {
                "success": True,
                "threats_found": 0,
                "threats": [],
                "warnings": ["No auth logs available"],
                "data": {
                    "failed_attempts_by_ip": {},
                    "invalid_users_by_ip": {},
                    "total_failed_attempts": 0
                },
                "recommendations": [
                    "Ensure logging is enabled",
                    "Check if logs are rotated"
                ]
            }

        # Parse log for failed attempts
        attempts = self._parse_failed_attempts(log_lines)

        # Group by IP
        attempts_by_ip = self._group_by_ip(attempts)

        # Detect brute force attacks
        threats = []
        for ip, attempt_list in attempts_by_ip.items():
            unique_users = set(a["username"] for a in attempt_list)
            invalid_count = sum(1 for a in attempt_list if a["is_invalid_user"])
            total_count = len(attempt_list)

            if total_count >= config.BRUTEFORCE_MAX_ATTEMPTS:
                severity = AttackSeverity.HIGH
                if total_count >= config.BRUTEFORCE_MAX_ATTEMPTS * 3:
                    severity = AttackSeverity.CRITICAL
                elif invalid_count >= config.BRUTEFORCE_INVALID_USER_THRESHOLD:
                    severity = AttackSeverity.CRITICAL

                threat = SecurityThreat(
                    threat_type="brute_force_attack",
                    severity=severity,
                    source_ip=ip,
                    description=f"Brute force attack from {ip}: {total_count} failed attempts",
                    timestamp=attempt_list[-1]["timestamp"],
                    details={
                        "attempt_count": total_count,
                        "unique_users": len(unique_users),
                        "invalid_user_attempts": invalid_count,
                        "first_attempt": attempt_list[0]["timestamp"],
                        "last_attempt": attempt_list[-1]["timestamp"],
                        "usernames": list(unique_users)[:10],
                        "protocols": list(set(a["protocol"] for a in attempt_list))
                    },
                    recommendations=[
                        f"Block IP {ip} using firewall (fail2ban recommended)",
                        "Disable password authentication for SSH",
                        "Use key-based authentication only",
                        "Change passwords for targeted accounts"
                    ]
                )
                threats.append(threat.to_dict())

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": [f"Brute force detected from {t['source_ip']}" for t in threats],
            "data": {
                "total_failed_attempts": len(attempts),
                "unique_source_ips": len(attempts_by_ip),
                "top_attackers": sorted(
                    [{"ip": ip, "attempts": len(a)} for ip, a in attempts_by_ip.items()],
                    key=lambda x: x["attempts"],
                    reverse=True
                )[:10]
            },
            "recommendations": [
                "Install and configure fail2ban",
                "Enable rate limiting in SSH",
                "Consider using port knocking",
                "Monitor logs regularly"
            ]
        }

    def _get_auth_logs(self) -> List[str]:
        """Get authentication logs from various sources"""
        log_lines = []

        # Try auth.log first
        for cmd in [self.AUTH_LOG_CMD, self.SECURE_LOG_CMD, self.JOURNALCTL_CMD]:
            stdout, _, code = self.executor.execute_with_shell(cmd)
            if code == 0 and stdout.strip():
                log_lines = stdout.strip().split('\n')
                break

        return log_lines

    def _parse_failed_attempts(self, log_lines: List[str]) -> List[Dict]:
        """Parse log lines for failed login attempts"""
        attempts = []

        for line in log_lines:
            # Try failed password pattern
            match = self.FAILED_PASSWORD_PATTERN.search(line)
            if match:
                attempts.append({
                    "timestamp": match.group(1),
                    "username": match.group(2),
                    "ip": match.group(3),
                    "is_invalid_user": "invalid user" in line.lower(),
                    "protocol": "ssh" if "ssh" in line.lower() else "unknown"
                })
                continue

            # Try invalid user pattern
            match = self.INVALID_USER_PATTERN.search(line)
            if match:
                attempts.append({
                    "timestamp": match.group(1),
                    "username": match.group(2),
                    "ip": match.group(3),
                    "is_invalid_user": True,
                    "protocol": "ssh"
                })

        return attempts

    def _group_by_ip(self, attempts: List[Dict]) -> Dict[str, List[Dict]]:
        """Group attempts by source IP"""
        by_ip = {}
        for attempt in attempts:
            ip = attempt["ip"]
            if ip not in by_ip:
                by_ip[ip] = []
            by_ip[ip].append(attempt)
        return by_ip


class PortScanDetector:
    """
    Service for detecting port scanning activity.
    - Detects rapid port connections from single IP
    - Analyzes reconnaissance patterns
    - Tracks multiple ports accessed by single IP
    """

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def detect_scan(self) -> Dict[str, Any]:
        """
        Detect port scanning activity.

        Returns:
            Dictionary with scan detection results
        """
        import config

        # Get connection history from various sources
        connections = self._get_connection_history()

        if not connections:
            return {
                "success": True,
                "threats_found": 0,
                "threats": [],
                "warnings": ["No connection data available"],
                "data": {
                    "scan_events": [],
                    "total_connections_analyzed": 0
                },
                "recommendations": []
            }

        # Analyze for port scan patterns
        scan_events = self._analyze_scan_patterns(connections)

        # Build threat list
        threats = []
        for event in scan_events:
            if event.is_scan:
                threat = SecurityThreat(
                    threat_type="port_scan",
                    severity=event.severity,
                    source_ip=event.ip_address,
                    description=f"Port scan detected from {event.ip_address}: {event.port_count} ports scanned",
                    timestamp=datetime.now().isoformat(),
                    details={
                        "ports_accessed": event.ports_accessed[:50],
                        "port_count": event.port_count,
                        "scan_pattern": event.scan_pattern.value,
                        "time_window": event.time_window
                    },
                    recommendations=[
                        f"Block IP {event.ip_address}",
                        "Monitor this IP for further activity",
                        "Consider using port knocking"
                    ]
                )
                threats.append(threat.to_dict())

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": [f"Port scan from {t['source_ip']}" for t in threats],
            "data": {
                "total_connections_analyzed": len(connections),
                "unique_source_ips": len(set(c.get("remote_ip", "") for c in connections)),
                "scan_events": [
                    {
                        "ip": e.ip_address,
                        "port_count": e.port_count,
                        "pattern": e.scan_pattern.value,
                        "severity": e.severity.value
                    }
                    for e in scan_events
                ]
            },
            "recommendations": [
                "Enable port scan detection in IDS",
                "Use firewall to block reconnaissance",
                "Hide non-essential services"
            ]
        }

    def _get_connection_history(self) -> List[Dict]:
        """Get connection history from netstat/ss"""
        # Reuse connection parsing logic
        connections = []

        cmd = "netstat -nt 2>/dev/null || ss -nt 2>/dev/null"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0 or not stdout.strip():
            return connections

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith("Proto") or line.startswith("State"):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            try:
                conn = {
                    "remote_addr": parts[4] if len(parts) > 4 else "",
                    "state": parts[5] if len(parts) > 5 else ""
                }

                if ":" in conn["remote_addr"]:
                    conn["remote_ip"] = conn["remote_addr"].rsplit(":", 1)[0]
                    conn["remote_port"] = int(conn["remote_addr"].rsplit(":", 1)[1])
                    connections.append(conn)
            except (ValueError, IndexError):
                continue

        return connections

    def _analyze_scan_patterns(self, connections: List[Dict]) -> List[PortScanEvent]:
        """Analyze connections for port scan patterns"""
        import config

        # Group by IP and collect ports
        ip_ports = {}
        for conn in connections:
            ip = conn.get("remote_ip", "")
            if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                continue

            if ip not in ip_ports:
                ip_ports[ip] = set()
            ip_ports[ip].add(conn.get("remote_port", 0))

        # Create scan events
        events = []
        for ip, ports in ip_ports.items():
            port_list = sorted(ports)

            # Determine scan pattern
            pattern = ScanPattern.COMMON
            if port_list:
                # Check if ports are sequential (linear scan)
                is_linear = all(
                    port_list[i] + 1 == port_list[i + 1]
                    for i in range(len(port_list) - 1)
                ) if len(port_list) > 1 else False

                if is_linear:
                    pattern = ScanPattern.LINEAR
                elif len(port_list) > 20:
                    pattern = ScanPattern.RANDOM

            event = PortScanEvent(
                ip_address=ip,
                ports_accessed=port_list,
                port_count=0,  # Will be set in __post_init__
                time_window=config.PORTSCAN_TIME_WINDOW,
                scan_pattern=pattern
            )
            events.append(event)

        return events


class SecurityLogAnalyzer:
    """
    Service for analyzing security logs for various threats.
    - Failed sudo attempts
    - Privilege escalation tries
    - Unknown user login attempts
    """

    # Commands for security log analysis
    SUDO_LOG_CMD = "grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -n 500"
    JOURNALCTL_CMD = "journalctl -n 1000 --no-pager 2>/dev/null"

    # Patterns for security events
    SUDO_FAILED_PATTERN = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*?sudo:.*?(\S+).*?command not allowed'
    )
    PRIVILEGE_ESCALATION_PATTERN = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*?pam_unix.*?authentication failure.*?user=(\S+)'
    )

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def analyze_logs(self) -> Dict[str, Any]:
        """
        Analyze security logs for threats.

        Returns:
            Dictionary with log analysis results
        """
        # Get security logs
        log_lines = self._get_security_logs()

        if not log_lines:
            return {
                "success": True,
                "threats_found": 0,
                "threats": [],
                "warnings": ["No security logs available"],
                "data": {
                    "events": [],
                    "failed_sudo_attempts": 0,
                    "privilege_escalation_attempts": 0
                },
                "recommendations": []
            }

        # Parse security events
        events = self._parse_security_events(log_lines)

        # Build threat list
        threats = []
        failed_sudo = [e for e in events if e.event_type == "failed_sudo"]
        priv_escalation = [e for e in events if e.event_type == "privilege_escalation"]

        if len(failed_sudo) >= 5:
            threat = SecurityThreat(
                threat_type="sudo_abuse",
                severity=AttackSeverity.MEDIUM,
                description=f"Multiple failed sudo attempts detected: {len(failed_sudo)} attempts",
                timestamp=datetime.now().isoformat(),
                details={
                    "attempts": len(failed_sudo),
                    "users": list(set(e.username for e in failed_sudo))
                },
                recommendations=[
                    "Review sudo logs for targeted accounts",
                    "Ensure sudo is properly configured",
                    "Consider implementing MFA"
                ]
            )
            threats.append(threat.to_dict())

        if priv_escalation:
            threat = SecurityThreat(
                threat_type="privilege_escalation",
                severity=AttackSeverity.HIGH,
                description=f"Privilege escalation attempts detected: {len(priv_escalation)} attempts",
                timestamp=datetime.now().isoformat(),
                details={
                    "attempts": len(priv_escalation),
                    "users": list(set(e.username for e in priv_escalation))
                },
                recommendations=[
                    "Investigate affected accounts",
                    "Check for compromised credentials",
                    "Review access controls"
                ]
            )
            threats.append(threat.to_dict())

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": [t["description"] for t in threats],
            "data": {
                "total_events": len(events),
                "failed_sudo_attempts": len(failed_sudo),
                "privilege_escalation_attempts": len(priv_escalation),
                "recent_events": [
                    {
                        "type": e.event_type,
                        "severity": e.severity.value,
                        "timestamp": e.timestamp,
                        "username": e.username,
                        "details": e.details
                    }
                    for e in events[:20]
                ]
            },
            "recommendations": [
                "Regularly review security logs",
                "Set up automated alerts for suspicious activity",
                "Implement log aggregation"
            ]
        }

    def _get_security_logs(self) -> List[str]:
        """Get security logs from various sources"""
        log_lines = []

        for cmd in [self.SUDO_LOG_CMD, self.JOURNALCTL_CMD]:
            stdout, _, code = self.executor.execute_with_shell(cmd)
            if code == 0 and stdout.strip():
                log_lines = stdout.strip().split('\n')
                break

        return log_lines

    def _parse_security_events(self, log_lines: List[str]) -> List[SecurityLogEvent]:
        """Parse log lines for security events"""
        events = []

        for line in log_lines:
            # Check for failed sudo
            match = self.SUDO_FAILED_PATTERN.search(line)
            if match:
                events.append(SecurityLogEvent(
                    event_type="failed_sudo",
                    severity=AttackSeverity.MEDIUM,
                    timestamp=match.group(1),
                    username=match.group(2),
                    details=line[:200]
                ))
                continue

            # Check for privilege escalation
            match = self.PRIVILEGE_ESCALATION_PATTERN.search(line)
            if match:
                events.append(SecurityLogEvent(
                    event_type="privilege_escalation",
                    severity=AttackSeverity.HIGH,
                    timestamp=match.group(1),
                    username=match.group(2),
                    details=line[:200]
                ))

        return events


class AnomalyDetector:
    """
    Service for detecting system anomalies.
    - Unknown/suspicious process names
    - Execution from /tmp or world-writable directories
    - High CPU usage from unknown processes
    - Cron job modifications
    """

    # Known legitimate process patterns
    KNOWN_PROCESSES = {
        "systemd", "sshd", "bash", "sh", "zsh", "python", "python3", "node",
        "nginx", "apache", "mysql", "postgres", "docker", "containerd",
        "kworker", "ksoftirqd", "migration", "rcu_", "dbus", "NetworkManager"
    }

    # Suspicious process patterns
    SUSPICIOUS_PATTERNS = [
        re.compile(r'^\d+$'),  # Numeric only process names
        re.compile(r'\.tmp$'),  # Ending in .tmp
        re.compile(r'tmp\d+'),  # tmp followed by numbers
        re.compile(r'\.\w{0,3}$'),  # Short extensionless names
    ]

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def detect_anomalies(self) -> Dict[str, Any]:
        """
        Detect system anomalies.

        Returns:
            Dictionary with anomaly detection results
        """
        import config

        anomalies = []
        warnings = []

        # Check for processes running from suspicious locations
        tmp_executions = self._check_tmp_executions()
        for proc in tmp_executions:
            anomalies.append(proc)
            warnings.append(f"Process executing from /tmp: {proc['command'][:50]}")

        # Check for high CPU unknown processes
        unknown_high_cpu = self._check_unknown_high_cpu()
        for proc in unknown_high_cpu:
            anomalies.append(proc)
            warnings.append(f"Unknown process with high CPU: {proc['process_name']}")

        # Check for world-writable executable files
        if config.ANOMALY_WORLD_WRITABLE_CHECK:
            world_writable = self._check_world_writable_executables()
            for item in world_writable:
                warnings.append(f"World-writable executable: {item}")

        # Check for suspicious cron jobs
        suspicious_crons = self._check_suspicious_crons()
        for cron in suspicious_crons:
            warnings.append(f"Suspicious cron job: {cron[:100]}")

        # Build threat list
        threats = []
        if tmp_executions:
            threat = SecurityThreat(
                threat_type="tmp_execution",
                severity=AttackSeverity.HIGH,
                description=f"Processes executing from /tmp: {len(tmp_executions)} found",
                timestamp=datetime.now().isoformat(),
                details={"executions": tmp_executions},
                recommendations=[
                    "Investigate processes running from /tmp",
                    "Kill suspicious processes",
                    "Scan for malware"
                ]
            )
            threats.append(threat.to_dict())

        if unknown_high_cpu:
            threat = SecurityThreat(
                threat_type="unknown_high_cpu",
                severity=AttackSeverity.HIGH,
                description=f"Unknown processes with high CPU: {len(unknown_high_cpu)} found",
                timestamp=datetime.now().isoformat(),
                details={"processes": unknown_high_cpu},
                recommendations=[
                    "Investigate high CPU processes",
                    "Check if legitimate application",
                    "Monitor for persistence"
                ]
            )
            threats.append(threat.to_dict())

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": warnings,
            "data": {
                "tmp_executions": tmp_executions,
                "unknown_high_cpu": unknown_high_cpu,
                "world_writable_count": len(world_writable) if config.ANOMALY_WORLD_WRITABLE_CHECK else 0,
                "suspicious_crons": suspicious_crons
            },
            "recommendations": [
                "Regular process monitoring",
                "Implement application whitelisting",
                "Review scheduled tasks"
            ]
        }

    def _check_tmp_executions(self) -> List[Dict]:
        """Check for processes running from /tmp or similar directories"""
        import config

        procs = []
        cmd = "ps -eo pid,cmd --no-headers"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0:
            return procs

        suspicious_paths = config.MALWARE_SUSPICIOUS_PATHS

        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split(None, 1)
            if len(parts) < 2:
                continue

            try:
                pid = int(parts[0])
                cmd = parts[1]

                # Check if running from suspicious path
                for path in suspicious_paths:
                    if path in cmd:
                        procs.append({
                            "pid": pid,
                            "command": cmd[:200]
                        })
                        break
            except (ValueError, IndexError):
                continue

        return procs

    def _check_unknown_high_cpu(self) -> List[Dict]:
        """Check for unknown processes with high CPU usage"""
        import config

        procs = []
        cmd = "ps -eo pid,%cpu,comm --no-headers --sort=-%cpu | head -n 20"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0:
            return procs

        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split(None, 2)
            if len(parts) < 3:
                continue

            try:
                pid = int(parts[0])
                cpu = float(parts[1])
                name = parts[2]

                if cpu >= config.ANOMALY_HIGH_CPU_THRESHOLD:
                    # Check if process name is known or suspicious
                    is_known = any(name.startswith(k) for k in self.KNOWN_PROCESSES)
                    is_suspicious = any(p.search(name) for p in self.SUSPICIOUS_PATTERNS)

                    if not is_known or is_suspicious:
                        procs.append({
                            "pid": pid,
                            "process_name": name,
                            "cpu_percent": cpu
                        })
            except (ValueError, IndexError):
                continue

        return procs

    def _check_world_writable_executables(self) -> List[str]:
        """Check for world-writable executable files"""
        results = []
        cmd = "find /tmp /var/tmp /dev/shm -type f -perm /o+w -executable 2>/dev/null"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code == 0:
            results = [line.strip() for line in stdout.strip().split('\n') if line.strip()]

        return results

    def _check_suspicious_crons(self) -> List[str]:
        """Check for suspicious cron jobs"""
        suspicious = []
        cmd = "crontab -l 2>/dev/null"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0:
            # Try listing all user crons
            cmd = "cat /etc/crontab /etc/cron.*/* 2>/dev/null"
            stdout, _, code = self.executor.execute_with_shell(cmd)

        if code == 0:
            for line in stdout.strip().split('\n'):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Look for suspicious patterns
                if any(s in line.lower() for s in ['wget', 'curl', 'nc -l', 'bash -i', '/tmp/']):
                    suspicious.append(line)

        return suspicious


class NetworkForensics:
    """
    Service for network forensics analysis.
    - Analyze suspicious outbound connections
    - Detect unknown listening ports
    - Check for connections to suspicious IPs
    """

    # Suspicious port ranges
    SUSPICIOUS_PORTS = {
        6667,  # IRC (common C2)
        4444,  # Metasploit default
        5555,  # Common backdoor
        31337, # Common backdoor
        12345, # Netbus
    }

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def analyze(self) -> Dict[str, Any]:
        """
        Perform network forensics analysis.

        Returns:
            Dictionary with forensics analysis results
        """
        # Get all network connections
        connections = self._get_all_connections()

        if not connections:
            return {
                "success": True,
                "threats_found": 0,
                "threats": [],
                "warnings": ["No network connection data available"],
                "data": {
                    "listening_ports": [],
                    "outbound_connections": [],
                    "suspicious_connections": []
                },
                "recommendations": []
            }

        # Analyze listening ports
        listening = [c for c in connections if c.state == "LISTEN"]

        # Analyze outbound connections
        outbound = [c for c in connections if c.is_outbound]

        # Identify suspicious connections
        suspicious = self._identify_suspicious(connections)

        # Build threat list
        threats = []
        warnings = []

        # Check for suspicious listening ports
        suspicious_listen = [c for c in listening if c.local_port in self.SUSPICIOUS_PORTS]
        if suspicious_listen:
            for conn in suspicious_listen:
                threats.append(SecurityThreat(
                    threat_type="suspicious_listening_port",
                    severity=AttackSeverity.HIGH,
                    description=f"Suspicious port listening: {conn.local_port} by {conn.process_name}",
                    timestamp=datetime.now().isoformat(),
                    details={
                        "port": conn.local_port,
                        "process": conn.process_name,
                        "pid": conn.pid,
                        "address": conn.local_address
                    },
                    recommendations=[
                        f"Investigate process {conn.process_name} (PID {conn.pid})",
                        "Verify if service is legitimate",
                        "Consider blocking port"
                    ]
                ).to_dict())
                warnings.append(f"Suspicious listening port: {conn.local_port}")

        # Check for unknown listening ports
        unknown_listen = [c for c in listening if c.local_port > 1024 and not c.process_name]
        if len(unknown_listen) > 5:
            threats.append(SecurityThreat(
                threat_type="unknown_listening_ports",
                severity=AttackSeverity.MEDIUM,
                description=f"Multiple unknown listening ports detected: {len(unknown_listen)}",
                timestamp=datetime.now().isoformat(),
                details={"ports": [c.local_port for c in unknown_listen[:10]]},
                recommendations=[
                    "Investigate unknown listening services",
                    "Verify legitimate applications",
                    "Document expected services"
                ]
            ).to_dict())

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": warnings,
            "data": {
                "listening_ports": [
                    {
                        "port": c.local_port,
                        "address": c.local_address,
                        "process": c.process_name,
                        "pid": c.pid
                    }
                    for c in listening
                ],
                "outbound_connections": [
                    {
                        "local_address": c.local_address,
                        "local_port": c.local_port,
                        "remote_address": c.remote_address,
                        "remote_port": c.remote_port,
                        "process": c.process_name,
                        "pid": c.pid
                    }
                    for c in outbound[:20]
                ],
                "suspicious_connections": [
                    {
                        "remote_address": c.remote_address,
                        "remote_port": c.remote_port,
                        "reason": c.reason,
                        "process": c.process_name
                    }
                    for c in suspicious
                ]
            },
            "recommendations": [
                "Document expected network services",
                "Monitor outbound connections",
                "Use network intrusion detection"
            ]
        }

    def _get_all_connections(self) -> List[NetworkConnection]:
        """Get all network connections with process info"""
        connections = []

        # Try ss with process info first
        cmd = "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0 or not stdout.strip():
            return connections

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith("Proto") or line.startswith("State"):
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            try:
                conn = NetworkConnection(
                    protocol=parts[0],
                    local_address=parts[3] if len(parts) > 3 else "",
                    local_port=0,
                    remote_address=parts[4] if len(parts) > 4 else "",
                    remote_port=0,
                    state=parts[1] if len(parts) > 1 else ""
                )

                # Parse addresses
                if ":" in conn.local_address:
                    addr_parts = conn.local_address.rsplit(":", 1)
                    conn.local_address = addr_parts[0]
                    conn.local_port = int(addr_parts[1])

                if ":" in conn.remote_address:
                    addr_parts = conn.remote_address.rsplit(":", 1)
                    conn.remote_address = addr_parts[0]
                    conn.remote_port = int(addr_parts[1])

                # Extract process info from last column
                if len(parts) > 6:
                    proc_info = " ".join(parts[6:])
                    if "pid=" in proc_info:
                        pid_match = re.search(r'pid=(\d+)', proc_info)
                        if pid_match:
                            conn.pid = int(pid_match.group(1))
                        name_match = re.search(r'name="([^"]+)"', proc_info)
                        if name_match:
                            conn.process_name = name_match.group(1)

                connections.append(conn)
            except (ValueError, IndexError):
                continue

        return connections

    def _identify_suspicious(self, connections: List[NetworkConnection]) -> List[NetworkConnection]:
        """Identify suspicious connections"""
        suspicious = []

        for conn in connections:
            conn.is_suspicious = False

            # Check for suspicious ports
            if conn.remote_port in self.SUSPICIOUS_PORTS:
                conn.is_suspicious = True
                conn.reason = f"Connecting to known suspicious port {conn.remote_port}"

            # Check for connections to non-standard ports
            if conn.remote_port > 1024 and conn.state == "ESTABLISHED":
                if not conn.process_name:
                    conn.is_suspicious = True
                    conn.reason = "Outbound connection from unknown process"

            if conn.is_suspicious:
                suspicious.append(conn)

        return suspicious


class MalwareDetector:
    """
    Service for detecting malware indicators.
    - Crypto miner detection (high CPU, unknown process)
    - Ransomware file patterns (.locked, .encrypted)
    - Execution from suspicious directories
    """

    # Crypto miner related keywords
    CRYPTO_KEYWORDS = [
        "miner", "xmrig", "cpuminer", "monero", "bitcoin",
        "crypto", "mining", "stratum", "pool"
    ]

    # Ransomware file extensions
    RANSOMWARE_EXTENSIONS = [
        ".locked", ".encrypted", ".crypt", ".crypto",
        ".krab", ".kkk", ".ccc", ".zzz"
    ]

    def __init__(self, executor: ISystemExecutor):
        self.executor = executor

    def detect_indicators(self) -> Dict[str, Any]:
        """
        Detect malware indicators.

        Returns:
            Dictionary with malware detection results
        """
        import config

        indicators = []
        threats = []
        warnings = []

        # Check for crypto miners
        miners = self._detect_crypto_miners()
        for miner in miners:
            indicators.append(miner)
            warnings.append(f"Potential crypto miner: {miner['process_name']}")

        # Check for ransomware files
        ransomware_files = self._check_ransomware_files()
        if ransomware_files:
            warnings.append(f"Ransomware file patterns found: {len(ransomware_files)} files")

        # Check for suspicious processes
        suspicious_procs = self._check_suspicious_processes()
        for proc in suspicious_procs:
            warnings.append(f"Suspicious process: {proc['process_name']}")

        # Build threat list
        if miners:
            threat = SecurityThreat(
                threat_type="crypto_mining",
                severity=AttackSeverity.CRITICAL,
                description=f"Potential crypto mining detected: {len(miners)} processes",
                timestamp=datetime.now().isoformat(),
                details={"miners": miners},
                recommendations=[
                    "Immediately investigate mining processes",
                    "Kill unauthorized mining processes",
                    "Scan for persistence mechanisms",
                    "Check how malware was introduced"
                ]
            )
            threats.append(threat.to_dict())

        if ransomware_files:
            threat = SecurityThreat(
                threat_type="ransomware_indicators",
                severity=AttackSeverity.CRITICAL,
                description=f"Ransomware indicators found: {len(ransomware_files)} encrypted files",
                timestamp=datetime.now().isoformat(),
                details={"files": ransomware_files[:20]},
                recommendations=[
                    "IMMEDIATE ACTION: Isolate affected system",
                    "Do NOT pay ransom",
                    "Check backups for recovery",
                    "Contact security incident response"
                ]
            )
            threats.append(threat.to_dict())

        return {
            "success": True,
            "threats_found": len(threats),
            "threats": threats,
            "warnings": warnings,
            "data": {
                "crypto_miners": miners,
                "ransomware_files": ransomware_files,
                "suspicious_processes": suspicious_procs,
                "total_indicators": len(indicators)
            },
            "recommendations": [
                "Run full system malware scan",
                "Monitor for file encryption activity",
                "Implement endpoint detection and response",
                "Regular backup verification"
            ]
        }

    def _detect_crypto_miners(self) -> List[Dict]:
        """Detect potential crypto mining processes"""
        import config

        miners = []
        cmd = "ps -eo pid,%cpu,comm,cmd --no-headers --sort=-%cpu | head -n 30"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0:
            return miners

        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split(None, 3)
            if len(parts) < 4:
                continue

            try:
                pid = int(parts[0])
                cpu = float(parts[1])
                name = parts[2]
                cmd = parts[3]

                # Check for high CPU
                if cpu >= config.MALWARE_CRYPTO_MINER_CPU:
                    # Check for crypto keywords
                    is_miner = (
                        any(keyword in name.lower() for keyword in self.CRYPTO_KEYWORDS) or
                        any(keyword in cmd.lower() for keyword in self.CRYPTO_KEYWORDS)
                    )

                    if is_miner:
                        miners.append({
                            "pid": pid,
                            "process_name": name,
                            "cpu_percent": cpu,
                            "command": cmd[:200]
                        })
                    elif not any(name.startswith(k) for k in AnomalyDetector.KNOWN_PROCESSES):
                        # Unknown high CPU process
                        miners.append({
                            "pid": pid,
                            "process_name": name,
                            "cpu_percent": cpu,
                            "command": cmd[:200],
                            "note": "Unknown high CPU process"
                        })
            except (ValueError, IndexError):
                continue

        return miners

    def _check_ransomware_files(self) -> List[str]:
        """Check for ransomware encrypted file patterns"""
        files = []

        # Build find command for ransomware extensions
        extensions = " -o ".join(f'-name "*{ext}"' for ext in self.RANSOMWARE_EXTENSIONS)
        cmd = f"find /home /var/www /tmp -type f \\( {extensions} \\) 2>/dev/null | head -n 50"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code == 0:
            files = [line.strip() for line in stdout.strip().split('\n') if line.strip()]

        return files

    def _check_suspicious_processes(self) -> List[Dict]:
        """Check for suspicious process characteristics"""
        import config

        suspicious = []
        cmd = "ps -eo pid,comm,cmd --no-headers"
        stdout, _, code = self.executor.execute_with_shell(cmd)

        if code != 0:
            return suspicious

        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split(None, 2)
            if len(parts) < 3:
                continue

            try:
                pid = int(parts[0])
                name = parts[1]
                cmd = parts[2]

                # Check for suspicious patterns
                is_suspicious = False
                reason = ""

                # Check for base64 encoded commands
                if "echo " in cmd and "base64" in cmd:
                    is_suspicious = True
                    reason = "Base64 encoded command execution"

                # Check for wget/curl to raw IPs
                if ("wget " in cmd or "curl " in cmd) and re.search(r'http://\d+\.\d+\.\d+\.\d+', cmd):
                    is_suspicious = True
                    reason = "Downloading from raw IP address"

                # Check for suspicious paths
                for path in config.MALWARE_SUSPICIOUS_PATHS:
                    if path in cmd and "exec" not in cmd.lower():
                        is_suspicious = True
                        reason = f"Executing from {path}"
                        break

                if is_suspicious:
                    suspicious.append({
                        "pid": pid,
                        "process_name": name,
                        "command": cmd[:200],
                        "reason": reason
                    })
            except (ValueError, IndexError):
                continue

        return suspicious
