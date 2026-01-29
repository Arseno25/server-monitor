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

# ============================================================================
# SECURITY DETECTION CONFIGURATION
# ============================================================================

# DDoS Detection thresholds
DDOS_CONN_THRESHOLD = int(os.getenv("DDOS_CONN_THRESHOLD", "100"))
DDOS_TIME_WINDOW = int(os.getenv("DDOS_TIME_WINDOW", "60"))
DDOS_SYN_FLOOD_RATIO = float(os.getenv("DDOS_SYN_FLOOD_RATIO", "0.5"))

# Bruteforce Detection
BRUTEFORCE_MAX_ATTEMPTS = int(os.getenv("BRUTEFORCE_MAX_ATTEMPTS", "10"))
BRUTEFORCE_TIME_WINDOW = int(os.getenv("BRUTEFORCE_TIME_WINDOW", "300"))
BRUTEFORCE_INVALID_USER_THRESHOLD = int(os.getenv("BRUTEFORCE_INVALID_USER_THRESHOLD", "3"))

# Port Scanning Detection
PORTSCAN_MIN_PORTS = int(os.getenv("PORTSCAN_MIN_PORTS", "10"))
PORTSCAN_TIME_WINDOW = int(os.getenv("PORTSCAN_TIME_WINDOW", "30"))

# Anomaly Detection
ANOMALY_TMP_EXECUTION = os.getenv("ANOMALY_TMP_EXECUTION", "true").lower() == "true"
ANOMALY_HIGH_CPU_THRESHOLD = float(os.getenv("ANOMALY_HIGH_CPU_THRESHOLD", "80"))
ANOMALY_WORLD_WRITABLE_CHECK = os.getenv("ANOMALY_WORLD_WRITABLE_CHECK", "true").lower() == "true"

# Malware Detection
MALWARE_CRYPTO_MINER_CPU = float(os.getenv("MALWARE_CRYPTO_MINER_CPU", "90"))
MALWARE_SUSPICIOUS_PATHS = os.getenv(
    "MALWARE_SUSPICIOUS_PATHS",
    "/tmp,/var/tmp,/dev/shm,/run/user"
).split(",")

# Known malicious IP sources (for checking - can be extended)
THREAT_INTEL_SOURCES = os.getenv(
    "THREAT_INTEL_SOURCES",
    "abuse.ch"  # SSL Blacklist
).split(",")
