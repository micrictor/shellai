from abc import abstractmethod
import multiprocessing
import os
import psutil

class CommandChecker:
    """Class to provide command existence checking functionality."""
    def __init__(self, parent_shell_pid, frida_script):
        self.parent_shell_pid = parent_shell_pid
        self.frida_script = frida_script

        # Import frida here so it can find its shared libraries.
        import frida
        self.session = frida.attach(int(self.parent_shell_pid))
        self.script = self.session.create_script(self.frida_script)
        self.script.load()
        self.api = self.script.exports

    def __getstate__(self):
        """We don't actually need to pickle this class."""
        return {}
    
    def __setstate__(self, state):
        """We don't actually need to pickle this class."""
        pass

    def check_command(self, command_string: str) -> bool:
        """
        Check if a command exists in the system PATH.
        
        If not implemented, return True by default.
        """
        result = False
        cmd = command_string.split()[0]
        try:
            result = self.api.check_command(cmd)
        except Exception as e:
            return True  # Fail open on error
        return result

class BaseTTY():
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""

    SHELL_NAME: str
    _cmd_checker: 'CommandChecker' = None
    _cmd_checker_cls: 'type[CommandChecker]' = CommandChecker
    _frida_script: str = ""

    def __init__(self):
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
        # Fork the process using double fork so the parent can exit immediately
        pid_1 = os.fork()
        if pid_1 > 0:
            # Parent process
            os._exit(0)  # Exit parent immediately
        
        pid_2 = os.fork()
        if pid_2 > 0:
            # First child process
            os._exit(0)  # Exit first child immediately

        # Second child, now orphaned, runs the writer
        self._write_to_tty(data)
        os._exit(0)  # Exit after writing

    def close(self):
        """Close the TTY file descriptor."""
        if self.tty_fd is not None:
            os.close(self.tty_fd)
            self.tty_fd = None
        self.tty_path = None

    @property
    def cmd_checker(self) -> 'CommandChecker':
        if self._cmd_checker is None:
            self._cmd_checker = self._cmd_checker_cls(self.parent_shell_pid, self._frida_script)
        return self._cmd_checker

    def check_command(self, command_string: str) -> bool:
       return self.cmd_checker.check_command(command_string)

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
