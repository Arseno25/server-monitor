"""
Application Layer - Services/Use Cases
Clean Architecture: Application Layer
Business logic for forensic diagnosis
"""
import json
import re
from typing import List, Dict, Any, Optional
import logging

from src.domain.entities import (
    ProcessInfo,
    DockerContainerState,
    DockerHealthState,
    ResourceLeakInfo,
    ConnectionStateCount,
    KernelMessage,
    KernelBufferResult,
    BackgroundTask,
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
