import os

from shellai.tty.base import BaseTTY, CommandChecker


file_directory = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(file_directory, "bash_frida.js"), "r") as f:
    _FRIDA_SCRIPT = f.read()


class BashTTY(BaseTTY):
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""
    SHELL_NAME = 'bash'
    _frida_script = _FRIDA_SCRIPT

    def __init__(self):
        super().__init__()

    @staticmethod
    def static_write_to_tty(ppid, data):
        """
        Write the given data to the TTY of the parent shell process.
        """
        # Import frida here so it can find its shared libraries.
        # Required because this method is called in a forked process.
        import frida
        session = frida.attach(int(ppid))

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
    tty = BashTTY()
    tty.open()
    tty.write("echo 'Hello from ShellAI!'")
    tty.close()
