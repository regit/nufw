from os import rename, chmod, unlink, access, F_OK
from logging import info, warning, error
from shutil import copyfile
from inl_tests.tools import tryRename
from errno import ENOENT

class BaseReplaceFile:
    def __init__(self, filename, file_mode=None):
        self.filename = filename
        self.file_mode = file_mode
        self.replaced = False
        self.installed = False
        self.filename_old = self.filename + ".old"

    def install(self):
        if self.installed:
            return
        self.installed = True
        if not access(self.filename_old, F_OK):
            self.replaced = tryRename(self.filename, self.filename_old)
            if self.replaced:
                warning("Replace file %s (existing renamed to %s)" % (self.filename, self.filename_old))
            else:
                warning("Install file %s" % self.filename)
        else:
            self.replaced = True
            warning("Install file %s (and keep old copy %s)" % (self.filename, self.filename_old))
        self.install_newfile()

    def install_newfile(self):
        pass

    def desinstall(self):
        if not self.installed:
            return
        if not self.replaced:
            return
        self.replaced = False
        warning("Restore old file %s" % self.filename)
        try:
            rename(self.filename_old, self.filename)
        except OSError, err:
            if err[0] == ENOENT:
                error("Unable to rename '%s' to '%s'" % (self.filename_old, self.filename))
            else:
                raise
        self.installed = False

    def __del__(self):
        self.desinstall()

class ReplaceFile(BaseReplaceFile):
    def __init__(self, filename, new_content, mode=None):
        BaseReplaceFile.__init__(self, filename, mode)
        self.new_content = new_content

    def install_newfile(self):
        output = open(self.filename, 'w')
        if self.file_mode is not None:
            chmod(self.filename, self.file_mode)
        if isinstance(self.new_content, str):
            output.write(self.new_content)
        else:
            self.new_content(output)
        output.close()
        del self.new_content

class TempCopyFile(BaseReplaceFile):
    def __init__(self, filename, new_filename, mode=None):
        BaseReplaceFile.__init__(self, filename, mode)
        self.new_filename = new_filename

    def install_newfile(self):
        copyfile(self.new_filename, self.filename)
        if self.file_mode is not None:
            chmod(self.filename, self.file_mode)

    def desinstall(self):
        if not self.installed:
            return
        if not self.replaced:
            self.installed = False
            try:
                unlink(self.filename)
            except OSError, err:
                if err.errno == ENOENT:
                    pass
                else:
                    raise
        else:
            BaseReplaceFile.desinstall(self)

