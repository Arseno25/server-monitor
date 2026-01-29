"""
Domain Entities - Data models for VPS Process Monitoring
Clean Architecture: Domain Layer
"""
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum


class ProcessState(Enum):
    """Process status based on ps stat column"""
    RUNNING = "R"           # Running
    SLEEPING = "S"          # Interruptible Sleep
    DISK_SLEEP = "D"        # Uninterruptible Sleep (IO Wait) - ANOMALY
    ZOMBIE = "Z"            # Zombie - ANOMALY
    STOPPED = "T"           # Stopped
    TRACING = "t"           # Tracing stop
    DEAD = "X"              # Dead
    IDLE = "I"              # Idle kernel thread


@dataclass
class ProcessInfo:
    """Process information from ps command"""
    pid: int
    ppid: int
    stat: str
    cpu_percent: float
    mem_percent: float
    elapsed_time: str
    command: str
    is_zombie: bool = False
    is_disk_sleep: bool = False
    
    def __post_init__(self):
        self.is_zombie = 'Z' in self.stat
        self.is_disk_sleep = 'D' in self.stat
    
    @property
    def is_anomaly(self) -> bool:
        """Check if process is an anomaly (zombie or disk sleep)"""
        return self.is_zombie or self.is_disk_sleep


@dataclass
class DockerHealthState:
    """Docker container health check state"""
    status: str = ""
    failing_streak: int = 0
    log: List[str] = field(default_factory=list)


@dataclass
class DockerContainerState:
    """Complete state of a Docker container"""
    container_name: str
    container_id: str
    status: str
    running: bool
    oom_killed: bool
    exit_code: int
    restart_count: int
    health: Optional[DockerHealthState] = None
    storage_driver: str = ""
    storage_data: dict = field(default_factory=dict)
    error_message: str = ""


@dataclass
class ConnectionStateCount:
    """Connection count by state"""
    state: str
    count: int
    is_warning: bool = False  # True if CLOSE_WAIT or TIME_WAIT is high


@dataclass
class ResourceLeakInfo:
    """Resource leak information (file descriptors, network connections)"""
    open_files_count: int
    open_files_limit: int
    fd_usage_percent: float
    connection_states: List[ConnectionStateCount] = field(default_factory=list)
    has_fd_leak: bool = False
    has_connection_leak: bool = False
    
    def __post_init__(self):
        if self.open_files_limit > 0:
            self.fd_usage_percent = (self.open_files_count / self.open_files_limit) * 100
            self.has_fd_leak = self.fd_usage_percent > 80  # Warning if > 80%


@dataclass
class KernelMessage:
    """Message from kernel ring buffer (dmesg)"""
    raw_line: str
    has_oom: bool = False
    has_segfault: bool = False
    has_kill: bool = False
    
    def __post_init__(self):
        lower_line = self.raw_line.lower()
        self.has_oom = "out of memory" in lower_line or "oom" in lower_line
        self.has_segfault = "segfault" in lower_line
        self.has_kill = "kill process" in lower_line or "killed" in lower_line
    
    @property
    def is_critical(self) -> bool:
        return self.has_oom or self.has_segfault or self.has_kill


@dataclass
class KernelBufferResult:
    """Result of kernel ring buffer analysis"""
    messages: List[KernelMessage] = field(default_factory=list)
    critical_count: int = 0
    oom_events: int = 0
    segfault_events: int = 0
    kill_events: int = 0


@dataclass
class BackgroundTask:
    """Background task consuming resources"""
    pid: int
    user: str
    cpu_percent: float
    mem_percent: float
    command: str
    is_resource_hog: bool = False

    def __post_init__(self):
        # Flag as resource hog if CPU > 10% or MEM > 5%
        self.is_resource_hog = self.cpu_percent > 10 or self.mem_percent > 5


# ============================================================================
# SECURITY DETECTION ENTITIES
# ============================================================================

class AttackSeverity(Enum):
    """Severity level of security threats"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanPattern(Enum):
    """Port scanning attack patterns"""
    LINEAR = "linear"  # Sequential ports
    RANDOM = "random"  # Random ports
    COMMON = "common"  # Common service ports


class AnomalyType(Enum):
    """Types of system anomalies"""
    SUSPICIOUS_PROCESS = "suspicious_process"
    TMP_EXECUTION = "tmp_execution"
    WORLD_WRITABLE_EXEC = "world_writable_exec"
    HIGH_CPU_UNKNOWN = "high_cpu_unknown"
    CRON_MODIFICATION = "cron_modification"


class MalwareType(Enum):
    """Types of malware indicators"""
    CRYPTO_MINER = "crypto_miner"
    RANSOMWARE = "ransomware"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    TROJAN = "trojan"


@dataclass
class ConnectionRateInfo:
    """Connection rate information for DDoS detection"""
    ip_address: str
    connection_count: int
    connections_per_second: float
    syn_recv_count: int = 0
    is_attack: bool = False
    ports_accessed: List[int] = field(default_factory=list)

    def __post_init__(self):
        # Flag as attack if high SYN_RECV count (SYN flood pattern)
        self.is_attack = self.syn_recv_count > self.connection_count * 0.5


@dataclass
class BruteForceAttempt:
    """Brute force attack attempt"""
    ip_address: str
    username: str
    attempt_count: int
    time_window: int  # seconds
    first_attempt: str
    last_attempt: str
    protocol: str = "ssh"  # ssh, ftp, etc.
    is_invalid_user: bool = False
    is_attack: bool = False

    def __post_init__(self):
        # Flag as attack if more than 5 attempts in time window
        self.is_attack = self.attempt_count >= 5


@dataclass
class PortScanEvent:
    """Port scanning detection event"""
    ip_address: str
    ports_accessed: List[int]
    port_count: int
    time_window: int  # seconds
    scan_pattern: ScanPattern = ScanPattern.COMMON
    is_scan: bool = False
    severity: AttackSeverity = AttackSeverity.LOW

    def __post_init__(self):
        # Determine if this is a port scan
        self.port_count = len(self.ports_accessed)
        self.is_scan = self.port_count >= 5

        # Set severity based on port count
        if self.port_count >= 50:
            self.severity = AttackSeverity.CRITICAL
        elif self.port_count >= 20:
            self.severity = AttackSeverity.HIGH
        elif self.port_count >= 10:
            self.severity = AttackSeverity.MEDIUM


@dataclass
class SecurityLogEvent:
    """Security log analysis event"""
    event_type: str  # failed_sudo, privilege_escalation, unknown_user, etc.
    severity: AttackSeverity
    timestamp: str
    username: str
    terminal: str = ""
    command: str = ""
    details: str = ""
    is_critical: bool = False

    def __post_init__(self):
        self.is_critical = self.severity in (AttackSeverity.HIGH, AttackSeverity.CRITICAL)


@dataclass
class AnomalyEvent:
    """System anomaly detection event"""
    anomaly_type: AnomalyType
    pid: int
    process_name: str
    command: str
    cpu_percent: float = 0.0
    mem_percent: float = 0.0
    executable_path: str = ""
    details: str = ""
    severity: AttackSeverity = AttackSeverity.LOW

    def __post_init__(self):
        # Determine severity based on anomaly type and CPU usage
        if self.anomaly_type == AnomalyType.TMP_EXECUTION:
            self.severity = AttackSeverity.HIGH
        elif self.anomaly_type == AnomalyType.HIGH_CPU_UNKNOWN and self.cpu_percent > 80:
            self.severity = AttackSeverity.CRITICAL


@dataclass
class NetworkConnection:
    """Network connection information for forensics"""
    protocol: str  # tcp, udp
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str  # ESTABLISHED, LISTEN, SYN_RECV, etc.
    pid: int = 0
    process_name: str = ""
    is_suspicious: bool = False
    reason: str = ""

    @property
    def remote_ip(self) -> str:
        """Extract remote IP from address"""
        if ":" in self.remote_address:
            return self.remote_address.split(":")[0]
        return self.remote_address

    @property
    def is_outbound(self) -> bool:
        """Check if this is an outbound connection"""
        return self.state == "ESTABLISHED" and self.remote_address not in (
            "0.0.0.0", "::", "127.0.0.1", "::1", ""
        )


@dataclass
class MalwareIndicator:
    """Malware detection indicator"""
    malware_type: MalwareType
    pid: int
    process_name: str
    command: str
    confidence: float  # 0.0 to 1.0
    indicators: List[str] = field(default_factory=list)
    severity: AttackSeverity = AttackSeverity.MEDIUM
    details: str = ""

    def __post_init__(self):
        # Set severity based on confidence and malware type
        if self.malware_type == MalwareType.RANSOMWARE:
            self.severity = AttackSeverity.CRITICAL
        elif self.confidence > 0.8:
            self.severity = AttackSeverity.HIGH
        elif self.confidence < 0.5:
            self.severity = AttackSeverity.LOW


@dataclass
class SecurityThreat:
    """Unified security threat report"""
    threat_type: str  # ddos, brute_force, port_scan, etc.
    severity: AttackSeverity
    source_ip: str = ""
    target: str = ""  # service, port, or process affected
    description: str = ""
    timestamp: str = ""
    details: dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert threat to dictionary"""
        return {
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "target": self.target,
            "description": self.description,
            "timestamp": self.timestamp,
            "details": self.details,
            "recommendations": self.recommendations
        }
