import os
import subprocess
import psutil
import tty

SUPPORTED_SHELLS = {'bash'}

class TTYWriter():
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""

    def __init__(self):
        self.tty_fd = None
        self.tty_path = None
        self.parent_shell_pid = None

    def open(self):
        """Find and open the TTY of the parent shell process."""
        self.parent_shell_pid = self._find_parent_shell()
        if self.parent_shell_pid is None:
            raise RuntimeError("Could not find parent shell process")
        
        # Get the TTY of the parent shell
        try:
            parent_proc = psutil.Process(self.parent_shell_pid)
            self.tty_path = parent_proc.terminal()
            if not self.tty_path:
                raise RuntimeError(f"Parent shell (PID {self.parent_shell_pid}) has no TTY")

            # Open the TTY for writing
            self.tty_fd = os.open(self.tty_path, os.O_WRONLY)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            raise RuntimeError(f"Could not open parent shell TTY: {e}")

    def _find_parent_shell(self):
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
                if parent_name in SUPPORTED_SHELLS:
                    return parent.pid

                current_proc = parent
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return None
    
    def _write_to_readline(self, data):
        """
        Use gdb to call readline functions in the parent shell process
        This is an incredible hack, but it works!
        """
        data = data.replace('"', r'\"').replace('\\', r'\\')
        run = subprocess.run([
            'gdb', '--batch',
            '-p', str(self.parent_shell_pid),
            '-ex', f'call (int)rl_replace_line("{data}", 0)',
            '-ex', f'call (int)rl_forward_byte({len(data)}, 0)',
            '-ex', 'call (void)rl_redisplay()',
            '-ex', 'detach',
            '-ex', 'quit'],
            capture_output=True)
        
        if run.returncode != 0:
            raise RuntimeError(f"Readline write command failed with return code {run.returncode}. Stderr: {run.stderr}")
        
    def _write_to_tty(self, data):
        if self.tty_fd is None:
            raise ValueError("TTY not opened. Call open() first.")
        
        # Ensure data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        os.write(self.tty_fd, data)

    def write(self, data):
        """Write data to the parent shell's TTY."""
        # Fork the process
        pid = os.fork()
        if pid == 0:
            # Child process
            self._write_to_readline(data)
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