import re
from inl_tests.replace_file import ReplaceFile
from logging import info
from config import NUAUTH_CONF

class NuauthConf(ReplaceFile):
    def __init__(self):
        ReplaceFile.__init__(self, NUAUTH_CONF, self.writeContent)

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

    def __setitem__(self, key, value):
#        if key not in self.content:
#            raise AttributeError("nuauth.conf has no key '%s'" % key)
        info("nuauth.conf: set %s=%s" % (key, value))
        self.content[key] = value

