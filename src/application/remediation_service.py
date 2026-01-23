"""
Application Layer - Remediation Service
Clean Architecture: Application Layer
Logic for performing remediation actions (kill process, restart container)
"""
from typing import Dict, Any, List
import logging

from src.domain.interfaces import ISystemExecutor

logger = logging.getLogger(__name__)


class RemediationService:
    """
    Service for performing remediation actions.
    Contains safety checks to prevent system instability.
    """
    
    # Critical system processes that should NEVER be killed
    PROTECTED_PROCESSES = [
        1,      # init/systemd
        'systemd',
        'init',
        'kthreadd',
        'sshd',
        'dockerd',
        'containerd',
        'bash', # Prevent killing own shell if running simple
        'python', # Prevent suicide (needs careful handling)
    ]
    
    def __init__(self, executor: ISystemExecutor):
        self.executor = executor
    
    def kill_process(self, pid: int, signal: int = 15) -> Dict[str, Any]:
        """
        Kill process based on PID.
        
        Args:
            pid: Process ID targeted
            signal: Signal (15=SIGTERM default, 9=SIGKILL force)
            
        Returns:
            Result dictionary
        """
        # Safety Check 1: Prevent killing PID 1
        if pid <= 1:
            return {
                "success": False,
                "error": "Safety Block: Cannot kill PID 1 (system critical)"
            }
            
        # Permission Check (simple)
        # Note: In real scenarios, we might check process name first
        
        success, message = self.executor.kill_process(pid, signal)
        
        return {
            "success": success,
            "pid": pid,
            "signal": signal,
            "message": message
        }
    
    def restart_container(self, container_name: str) -> Dict[str, Any]:
        """
        Restart docker container.
        
        Args:
            container_name: Name or ID of container
        
        Returns:
            Result dictionary
        """
        if not container_name or len(container_name) < 2:
            return {
                "success": False,
                "error": "Invalid container name"
            }
            
        success, message = self.executor.restart_container(container_name)
        
        return {
            "success": success,
            "container": container_name,
            "action": "restart",
            "message": message
        }
