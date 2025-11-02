import os

from shellai.tty.base import BaseTTY


file_directory = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(file_directory, "zsh_frida.js"), "r") as f:
    _FRIDA_SCRIPT = f.read()

class ZshTTYWriter(BaseTTY):
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""
    SHELL_NAME = 'zsh'
    def __init__(self):
        super().__init__()
    
    def _write_to_tty(self, data):
        """
        Write the given data to the TTY of the parent shell process.
        """
        # Import frida here so it can find its shared libraries.
        # Required because this method is called in a forked process.
        import frida
        session = frida.attach(int(self.parent_shell_pid))

        # If anything fails after we attach, we need to detach or the user's shell freezes
        try:
            script = session.create_script(_FRIDA_SCRIPT)
            script.load()
            api = script.exports
            api.write_to_tty(data)
        except Exception as e:
            print(f"Error while writing back to shell: {e}", flush=True)
        finally:
            session.detach()
        
        

if __name__ == "__main__":
    writer = ZshTTYWriter()
    writer.open()
    writer.write("echo 'Hello from ShellAI!'")
    writer.close()
