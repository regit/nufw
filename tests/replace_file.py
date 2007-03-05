from os import rename, chmod
from errno import ENOENT, EACCES
from logging import info, warning

def try_rename(before, after):
    """
    Try to rename file 'before' to 'after'.
    Return True on sucess, False if original file doesn't exist.
    Raise RuntimeError() on permission error.
    """
    try:
        rename(before, after)
        return True
    except OSError, err:
        code = err[0]
        if code == ENOENT:
            info("Unable to rename %r to %r: original file doesn't exist" % (before, after))
            return False
        if code == EACCES:
            raise RuntimeError('Permission denied (retry program with root access)')
        raise

class ReplaceFile:
    def __init__(self, filename, new_content, mode=None):
        self.has_original = False
        self.replaced = False
        self.installed = False
        self.filename = filename
        self.filename_old = self.filename + ".old"
        self.mode = mode
        self.new_content = new_content

    def install(self):
        if self.installed:
            return
        self.installed = True
        self.replaced = try_rename(self.filename, self.filename_old)
        if self.replaced:
            warning("Replace file %s (existing renamed to %s)" % (self.filename, self.filename_old))
        else:
            warning("Install file %s" % self.filename)
        output = open(self.filename, 'w')
        if self.mode is not None:
            chmod(self.filename, self.mode)
        if isinstance(self.new_content, str):
            output.write(self.new_content)
        else:
            self.new_content(output)
        output.close()

    def desinstall(self):
        if not self.replaced:
            return
        self.replaced = False
        self.installed = False
        #unlink(self.filename)
        warning("Restore old file %s" % self.filename)
        rename(self.filename_old, self.filename)

    def __del__(self):
        self.desinstall()

