"""
Presentation Layer - MCP Tools
Clean Architecture: Presentation Layer
MCP tool definitions using FastMCP
"""
from typing import Optional
from mcp.server.fastmcp import FastMCP

from src.infrastructure import get_system_executor
from src.application import (
    ProcessAnalyzer,
    DockerInspector,
    ResourceLeakDetector,
    KernelBufferReader,
    BackgroundTaskAnalyzer,
    RemediationService,
)


def register_tools(mcp: FastMCP) -> None:
    """
    Register all MCP tools to the server instance.
    
    Args:
        mcp: FastMCP server instance
    """
    executor = get_system_executor()
    
    # Initialize services
    process_analyzer = ProcessAnalyzer(executor)
    docker_inspector = DockerInspector(executor)
    resource_detector = ResourceLeakDetector(executor)
    kernel_reader = KernelBufferReader(executor)
    background_analyzer = BackgroundTaskAnalyzer(executor)
    remediator = RemediationService(executor)
    
    @mcp.tool()
    def scan_process_anomalies() -> dict:
        """
        Scan system to detect stuck processes, zombies, or uninterruptible sleep states.
        
        Tool uses `ps -eo pid,ppid,stat,%cpu,%mem,etime,cmd` to:
        - Detect Zombie processes (stat 'Z') - processes finished but not cleaned up by parent
        - Detect Disk Sleep processes (stat 'D') - processes stuck waiting for I/O
        
        Returns:
            Dictionary containing:
            - total_processes: Total count of processes
            - anomaly_count: Count of anomalous processes
            - zombies: List of zombie processes
            - disk_sleep: List of processes in disk sleep
            - all_processes: Sample of all processes (max 100)
        
        Use Case:
        Use when user reports system hang or unresponsive processes,
        but CPU/Memory usage appears normal.
        """
        return process_analyzer.scan_anomalies()
    
    @mcp.tool()
    def deep_docker_inspect(container_name: str) -> dict:
        """
        Deep inspection of Docker containers to find hidden issues.
        
        Tool uses `docker inspect` to extract:
        - OOMKilled: Whether container was killed by OOM Killer
        - ExitCode: Last exit code
        - RestartCount: How many times container has restarted
        - Health: Health check status (if configured)
        - Storage: Overlay2 storage information
        
        Args:
            container_name: Name or ID of Docker container
        
        Returns:
            Dictionary containing container state details and warnings
        
        Use Case:
        Use when container appears "Up" but malfunctioning,
        or after unexplained container restarts.
        """
        return docker_inspector.inspect_container(container_name)
    
    @mcp.tool()
    def check_resource_leaks() -> dict:
        """
        Detect file descriptor exhaustion and network connection leaks.
        
        Tool checks:
        1. File Descriptors:
           - `lsof | wc -l` to count open files
           - `ulimit -n` to get limit
           - Warning if usage > 80%
        
        2. Network Connections:
           - `netstat -tan` or `ss -tan` to view connection states
           - Warning if CLOSE_WAIT > 100 (potential connection leak)
           - Warning if TIME_WAIT > 500 (high connection churn)
        
        Returns:
            Dictionary containing:
            - file_descriptors: Open count, limit, usage percent
            - connections: List of connection states with count
            - warnings: List of potential issues
        
        Use Case:
        Use when application slowly becomes unresponsive,
        or when new connections fail without clear errors.
        """
        return resource_detector.check_leaks()
    
    @mcp.tool()
    def read_kernel_ring_buffer(lines: int = 50) -> dict:
        """
        Read kernel ring buffer (dmesg) to catch errors not recorded in app logs.
        
        Tool uses `dmesg | tail -n <lines>` and searches for:
        - "Out of memory" or "OOM" - System ran out of memory
        - "segfault" - Program crash due to invalid memory access
        - "Kill process" or "killed" - Process forcibly terminated
        
        Args:
            lines: Number of last lines to read (default: 50)
        
        Returns:
            Dictionary containing:
            - total_lines: Number of lines read
            - critical_count: Number of critical events
            - summary: Summary of OOM, segfault, kill events
            - critical_events: Details of each critical event
            - recent_messages: Last 20 messages
        
        Use Case:
        Use when process dies suddenly without logs,
        or when suspecting memory issues at OS level.
        
        Note: May require sudo for dmesg access.
        """
        return kernel_reader.read_buffer(lines=lines)
    
    @mcp.tool()
    def analyze_background_tasks(min_cpu: float = 0.0, min_mem: float = 0.0) -> dict:
        """
        List all non-root background processes using resources.
        
        Tool uses:
        `ps -eo user,pid,%cpu,%mem,cmd | grep -v '^root' | sort -k3 -rn`
        
        To find "hidden" resource hogs that might not be visible
        in standard monitoring tools.
        
        Args:
            min_cpu: Minimum CPU% to include (default: 0.0)
            min_mem: Minimum MEM% to include (default: 0.0)
        
        Returns:
            Dictionary containing:
            - total_tasks: Total number of background tasks
            - resource_hogs_count: Number categorized as resource hog
            - resource_hogs: Process details with CPU > 10% or MEM > 5%
            - all_tasks: Sample of all tasks (max 50)
        
        Use Case:
        Use when system feels slow but no process clearly shows
        high resource usage.
        """
        return background_analyzer.analyze(min_cpu=min_cpu, min_mem=min_mem)

    @mcp.tool()
    def kill_process(pid: int, signal: int = 15) -> dict:
        """
        Terminate a process based on PID.
        
        ⚠️ CAUTION: Use this tool ONLY if sure the process is safe to stop.
        Never kill system processes (PID <= 1, kthreadd, systemd, etc).
        
        Args:
            pid: Process ID to kill.
            signal: Signal number. Use 15 (SIGTERM) for graceful stop, or 9 (SIGKILL) for force kill. Default: 15.
            
        Returns:
            Dictionary with success/failure status.
        
        Use Case:
        Use after finding Zombie process or stuck process not responding,
        and user approves functionality.
        """
        return remediator.kill_process(pid=pid, signal=signal)

    @mcp.tool()
    def restart_container(container_name: str) -> dict:
        """
        Restart malfunctioning Docker container.
        
        Tool executes `docker restart <container_name>`.
        
        Args:
            container_name: Container name or ID.
            
        Returns:
            Dictionary with success/failure status.
            
        Use Case:
        Use if `deep_docker_inspect` shows container state unhealthy
        or stuck, and restart is needed for recovery.
        """
        return remediator.restart_container(container_name=container_name)
