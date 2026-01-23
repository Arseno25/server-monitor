"""
Infrastructure Layer - System Command Executor
Clean Architecture: Infrastructure Layer
Implementation of subprocess for Linux command execution
"""
import subprocess
import shutil
from typing import Tuple
import logging

from src.domain.interfaces import ISystemExecutor

logger = logging.getLogger(__name__)


class SystemExecutor(ISystemExecutor):
    """
    Implementation of ISystemExecutor using subprocess.
    Handles Linux command execution with graceful error handling.
    """
    
    def execute(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Execute command without shell (safer).
        
        Args:
            command: Command string (will be split)
            timeout: Timeout in seconds
            
        Returns:
            Tuple (stdout, stderr, return_code)
        """
        try:
            args = command.split()
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timeout: {command}")
            return "", f"Command timed out after {timeout} seconds", -1
            
        except PermissionError as e:
            logger.warning(f"Permission denied: {command}")
            return "", f"Permission denied: {str(e)}", -2
            
        except FileNotFoundError as e:
            logger.warning(f"Command not found: {command}")
            return "", f"Command not found: {str(e)}", -3
            
        except Exception as e:
            logger.error(f"Error executing command: {command} - {str(e)}")
            return "", f"Error: {str(e)}", -99
    
    def execute_with_shell(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Execute command with shell=True.
        Used for commands with pipes (|) or redirects.
        
        Args:
            command: Full command string with pipes/redirects
            timeout: Timeout in seconds
            
        Returns:
            Tuple (stdout, stderr, return_code)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timeout: {command}")
            return "", f"Command timed out after {timeout} seconds", -1
            
        except PermissionError as e:
            logger.warning(f"Permission denied: {command}")
            return "", f"Permission denied: {str(e)}", -2
            
        except Exception as e:
            logger.error(f"Error executing command: {command} - {str(e)}")
            return "", f"Error: {str(e)}", -99
    
    def is_command_available(self, command: str) -> bool:
        """
        Check if command is available on the system using shutil.which
        
        Args:
            command: Command name (e.g., 'docker', 'netstat')
            
        Returns:
            True if command is available
        """
        return shutil.which(command) is not None

    def kill_process(self, pid: int, signal: int = 15) -> Tuple[bool, str]:
        """
        Kill process with specific signal.
        Ref: kill -<signal> <pid>
        """
        try:
            cmd = f"kill -{signal} {pid}"
            stdout, stderr, code = self.execute(cmd)
            
            if code == 0:
                return True, f"Process {pid} killed with signal {signal}"
            else:
                return False, f"Failed to kill process {pid}: {stderr}"
                
        except Exception as e:
            return False, f"Error killing process: {str(e)}"

    def restart_container(self, container_name: str) -> Tuple[bool, str]:
        """
        Restart docker container.
        Ref: docker restart <container>
        """
        if not self.is_command_available("docker"):
            return False, "Docker command not available"
            
        try:
            cmd = f"docker restart {container_name}"
            stdout, stderr, code = self.execute(cmd)
            
            if code == 0:
                return True, f"Container {container_name} restarted successfully"
            else:
                return False, f"Failed to restart container {container_name}: {stderr}"
                
        except Exception as e:
            return False, f"Error restarting container: {str(e)}"


# Singleton instance untuk dependency injection
_executor_instance = None


def get_system_executor() -> SystemExecutor:
    """Factory function untuk mendapatkan SystemExecutor instance"""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = SystemExecutor()
    return _executor_instance
