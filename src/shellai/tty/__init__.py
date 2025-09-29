from .bash import BashTTYWriter
from .zsh import ZshTTYWriter

WRITERS = {
    BashTTYWriter,
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
        self.writer.close()
