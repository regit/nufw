import re
from inl_tests.replace_file import ReplaceFile
from logging import info
from config import NUAUTH_CONF
from os.path import abspath, dirname, join

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
            if re.match("^include", line):
                self.parse_include(line)
                continue
            line = line.split("=", 1)
            if len(line) != 2:
                raise Exception("Line %s has no '='" % line)
            key, value = line
            self.content[key] = value

        # default values
        self["nuauth_tls_cacert"] = '"%s"' % abspath("./pki/CA.crt")
        self["nuauth_tls_key"] = '"%s"' % abspath("./pki/nuauth.inl.fr.key")
        self["nuauth_tls_cert"] = '"%s"' % abspath("./pki/nuauth.inl.fr.crt")
        self["nuauth_tls_request_cert"] = "0"
        self["nuauth_tls_disable_nufw_fqdn_check"] = "1"

    def parse_include(self, line):
        conf_dir = dirname(self.filename)
        (ignored,filename) = line.split(" ", 1)
        filename = filename.strip('"')
        included_file = join(conf_dir,filename)

        for line in open(included_file):
            line = re.sub("#.*", "", line)
            line = line.strip()
            if not line:
                continue
            if re.match("^include", line):
                raise Exception("Nested includes forbidden ! (line '%s' from file %s)" % (line,included_file))
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
        if key in ("nuauth_tls_cacert", "nuauth_tls_key", "nuauth_tls_cert", "nuauth_do_ip_authentication"):
            return True
        return False

    def __setitem__(self, key, value):
        if self.needRestart(key, value):
            self.need_restart = True
        info("nuauth.conf: set %s=%s" % (key, value))
        self.content[key] = value

