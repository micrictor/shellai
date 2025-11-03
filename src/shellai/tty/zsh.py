import os

from shellai.tty.base import BaseTTY


file_directory = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(file_directory, "zsh_frida.js"), "r") as f:
    _FRIDA_SCRIPT = f.read()

class ZshTTYWriter(BaseTTY):
    """Class to handle writing an arbitrary string to the TTY of the parent shell process."""
    SHELL_NAME = 'zsh'
    _frida_script = _FRIDA_SCRIPT

    def __init__(self):
        super().__init__()


if __name__ == "__main__":
    writer = ZshTTYWriter()
    writer.open()
    writer.write("echo 'Hello from ShellAI!'")
    writer.close()
