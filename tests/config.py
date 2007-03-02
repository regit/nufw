import re
from replace_file import ReplaceFile

class NuauthConf(ReplaceFile):
    def __init__(self, filename):
        ReplaceFile.__init__(self, filename, self.writeContent)

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
        output.close()

    def __setitem__(self, key, value):
        if key not in self.content:
            raise AttributeError("nuauth.conf has no key '%s'" % key)
        self.content[key] = value

