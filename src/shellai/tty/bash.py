import subprocess

from .base import BaseTTYWriter

SUPPORTED_SHELLS = {'bash'}

class BashTTYWriter(BaseTTYWriter):
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""
    SHELL_NAME = 'bash'
    def __init__(self):
        super().__init__()
    
    def _write_to_tty(self, data):
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
