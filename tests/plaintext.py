from config import CONF_DIR
from common import createClient
from inl_tests.replace_file import ReplaceFile
from os.path import join as path_join
from logging import info

class PlaintextUser:
    def __init__(self, login, password, uid, gid):
        self.login = login
        self.password = password
        self.uid = uid
        self.gid = gid

    def createClient(self, more_args=None):
        return createClient(self.login, self.password, more_args=more_args)

    def __str__(self):
        return "%s:%s:%u:%u" % (self.login, self.password, self.uid, self.gid)

class PlaintextUserDB:
    def __init__(self):
        self.filename = path_join(CONF_DIR, "users.nufw")
        self.users = []
        self.replace = None

    def addUser(self, user):
        self.users.append(user)

    def install(self, config):
        info("Setup Plaintext user database")
        text = []
        for user in self.users:
            user_text = str(user)
            info("Add user: %s" % user_text)
            text.append(user_text)
        text = "\n".join(text)+"\n"
        self.replace = ReplaceFile(self.filename, text)
        self.replace.install()

        config["nuauth_user_check_module"] = '"plaintext"'
        config["plaintext_userfile"] = '"%s"' % self.filename

    def desinstall(self):
        if self.replace:
            info("Reset Plaintext user database")
            self.replace.desinstall()

    def __getitem__(self, key):
        return self.users[key]

USERDB = PlaintextUserDB()
USERDB.addUser( PlaintextUser("username", "password", 42, 42) )
USERDB.addUser( PlaintextUser("username2", "password2", 43, 43) )

class PlaintextAcl:
    def __init__(self):
        self.filename = path_join(CONF_DIR, "acls.nufw")
        self.replace = None
        self.content = []

    def addAcl(self, name, port, gid, decision=1, **kw):
        text = [
            "[%s]" % name,
            "decision=%s" % decision,
            "gid=%u" % gid,
            "proto=6",
            "SrcIP=0.0.0.0/0",
            "SrcPort=1024-65535",
            "DstIP=0.0.0.0/0",
            "DstPort=%u" % port]
        for key, value in kw.iteritems():
            text.append("%s=%s" % (key, value))
        self.content.extend(text)

    def install(self, config):
        info("Setup Plaintext ACL")
        for line in self.content:
            info("Plaintext ACL: %s" % line)

        text = "\n".join(self.content)
        self.replace = ReplaceFile(self.filename, text)
        self.replace.install()

        config["plaintext_aclfile"] = '"%s"' % self.filename
        config["nuauth_acl_check_module"] = '"plaintext"'

    def desinstall(self):
        if self.replace:
            info("Reset Plaintext ACL")
            self.replace.desinstall()

