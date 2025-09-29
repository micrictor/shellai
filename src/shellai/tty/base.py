from abc import abstractmethod
import os
import psutil

class BaseTTYWriter():
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""

    SHELL_NAME: str

    def __init__(self):
        self.tty_fd = None
        self.tty_path = None
        self.parent_shell_pid = None

    def open(self):
        """Find and open the TTY of the parent shell process."""
        self.parent_shell_pid = self.find_parent_shell()
        if self.parent_shell_pid is None:
            raise RuntimeError("Could not find parent shell process")

    def find_parent_shell(self):
        """Find the PID of the parent shell process (bash, zsh, sh, ash, etc.)."""
        try:
            current_proc = psutil.Process()
            
            # Walk up the process tree to find a shell
            while current_proc:
                parent = current_proc.parent()
                if parent is None:
                    break
                    
                # Check if parent process name is a known shell
                parent_name = parent.name().lower()
                if parent_name == self.SHELL_NAME:
                    return parent.pid

                current_proc = parent
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return None

    @abstractmethod
    def _write_to_tty(self, data):
        pass

    def write(self, data):
        """Write data to the parent shell's TTY."""
        # Fork the process
        pid = os.fork()
        if pid == 0:
            # Child process
            self._write_to_tty(data)
        else:
            # Parent process
            os._exit(0)  # Exit parent immediately


    def close(self):
        """Close the TTY file descriptor."""
        if self.tty_fd is not None:
            os.close(self.tty_fd)
            self.tty_fd = None
        self.tty_path = None

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()