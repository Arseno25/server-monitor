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
