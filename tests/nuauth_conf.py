import re
from inl_tests.replace_file import ReplaceFile
from logging import info
from config import NUAUTH_CONF

class NuauthConf(ReplaceFile):
    def __init__(self):
        ReplaceFile.__init__(self, NUAUTH_CONF, self.writeContent)
        self.need_restart = False

        # Load current configuration
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

    def writeContent(self, output):
        for key, value in self.content.iteritems():
            output.write("%s=%s\n" % (key, value))

    def __getitem__(self, key):
        try:
            value = self.content[key]
        except KeyError:
            raise AttributeError("nuauth.conf has no key '%s'" % key)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return value

    def needRestart(self, key, newvalue):
        if self.need_restart:
            return True
        if key in self.content and self.content[key] == newvalue:
            return False
        if key in ("nuauth_tls_cacert", "nuauth_tls_key", "nuauth_tls_cert"):
            return True
        return False

    def __setitem__(self, key, value):
        if self.needRestart(key, value):
            self.need_restart = True
        self.content[key] = value

