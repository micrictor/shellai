from .bash import BashTTY
from .zsh import ZshTTYWriter

WRITERS = {
    BashTTY,
    ZshTTYWriter
}

SUPPORTED_SHELLS = {writer.SHELL_NAME: writer for writer in WRITERS}

class GenericTTYWriter:
    def __enter__(self):
        """Context manager entry."""
        for writer in WRITERS:
            if writer().find_parent_shell() is not None:
                self.writer = writer()
                break
        else:
            raise StopIteration("No supported parent shell found.")
        self.writer.open()
        return self.writer

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        pass

def write_to_tty(frida_script: str, ppid: int, data: str):
    """
    Write the given data to the TTY of the parent shell process.
    """
    # Import frida here so it can find its shared libraries.
    # Required because this method is called in a forked process.
    import frida
    session = frida.attach(int(ppid))

    # If anything fails after we attach, we need to detach or the user's shell freezes
    try:
        script = session.create_script(frida_script)
        script.load()
        api = script.exports
        api.write_to_tty(data)
    except Exception as e:
            print(f"Error while writing back to shell: {e}", flush=True)
    finally:
        session.detach()