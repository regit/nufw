import re
from os import rename, unlink

class NuauthConf:
    def __init__(self, filename):
        self.filename = filename
        self.filename_old = self.filename + ".old"
        self.replaced = False
        self.content = {}
        for line in open(self.filename):
            line = re.sub("#.*", "", line)
            line = line.strip()
            if not line:
                continue
            line = line.split("=", 1)
            if len(line) != 2:
                raise Exception("Line %s has no '='" % line)
            key, value = line
            self.content[key] = value

    def __del__(self):
        self.desinstall()

    def __setitem__(self, key, value):
        if key not in self.content:
            raise AttributeError("nuauth.conf has no key '%s'" % key)
        self.content[key] = value

    def install(self):
        try:
            rename(self.filename, self.filename_old)
        except OSError, err:
            code = err[0]
            if code == 13:
                raise RuntimeError('Permission denied (retry program with root access)')
            else:
                raise
        self.replaced = True

        print "WRITE %s" % self.filename
        output = open(self.filename, 'w')
        for key, value in self.content.iteritems():
            output.write("%s=%s\n" % (key, value))
        output.close()

    def desinstall(self):
        if not self.replaced:
            return
        self.replaced = False
        unlink(self.filename)
        rename(self.filename_old, self.filename)

