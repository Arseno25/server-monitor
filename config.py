"""
Configuration for VPS Process Monitoring MCP Server
"""
import os

# Timeout for command execution (in seconds)
COMMAND_TIMEOUT = int(os.getenv("VPS_MONITOR_TIMEOUT", "30"))

# Thresholds for warnings
FD_WARNING_PERCENT = float(os.getenv("VPS_MONITOR_FD_WARNING", "80"))
CLOSE_WAIT_THRESHOLD = int(os.getenv("VPS_MONITOR_CLOSE_WAIT_THRESHOLD", "100"))
TIME_WAIT_THRESHOLD = int(os.getenv("VPS_MONITOR_TIME_WAIT_THRESHOLD", "500"))

# Logging level
LOG_LEVEL = os.getenv("VPS_MONITOR_LOG_LEVEL", "INFO")

# Maximum output limits
MAX_PROCESS_OUTPUT = int(os.getenv("VPS_MONITOR_MAX_PROCESSES", "100"))
MAX_TASK_OUTPUT = int(os.getenv("VPS_MONITOR_MAX_TASKS", "50"))
MAX_DMESG_LINES = int(os.getenv("VPS_MONITOR_MAX_DMESG", "100"))
