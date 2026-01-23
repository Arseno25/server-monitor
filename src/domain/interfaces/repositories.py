"""
Domain Interfaces - Abstract contracts for infrastructure
Clean Architecture: Domain Layer
"""
from abc import ABC, abstractmethod
from typing import Tuple, Optional


class ISystemExecutor(ABC):
    """
    Interface for system command execution.
    Implementation will use subprocess for Linux commands.
    """
    
    @abstractmethod
    def execute(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Execute command and return (stdout, stderr, return_code)
        
        Args:
            command: Command string to execute
            timeout: Timeout in seconds
            
        Returns:
            Tuple (stdout, stderr, return_code)
        """
        pass
    
    @abstractmethod
    def execute_with_shell(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Execute command with shell=True (for pipes, redirects)
        
        Args:
            command: Command string with pipes/redirects
            timeout: Timeout in seconds
            
        Returns:
            Tuple (stdout, stderr, return_code)
        """
        pass
    
    @abstractmethod
    def is_command_available(self, command: str) -> bool:
        """
        Check if command is available on the system
        
        Args:
            command: Command name (e.g., 'docker', 'netstat')
            
        Returns:
            True if command is available
        """
        pass

    @abstractmethod
    def kill_process(self, pid: int, signal: int = 15) -> Tuple[bool, str]:
        """
        Kill process with specific signal.
        
        Args:
            pid: Process ID
            signal: Signal number (15=SIGTERM, 9=SIGKILL)
            
        Returns:
            Tuple (success, message)
        """
        pass

    @abstractmethod
    def restart_container(self, container_name: str) -> Tuple[bool, str]:
        """
        Restart docker container.
        
        Args:
            container_name: Name or ID of container
            
        Returns:
            Tuple (success, message)
        """
        pass
