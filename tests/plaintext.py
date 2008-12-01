from config import CONF_DIR
from common import createClient, createClientWithCerts
from inl_tests.replace_file import ReplaceFile
from os.path import join as path_join
from os.path import exists as path_exists
from os import remove
from os import rmdir
from logging import info
from tempfile import mkdtemp

class PlaintextUser:
    def __init__(self, login, password, uid, gid):
        self.login = login
        self.password = password
        self.uid = uid
        self.gid = gid

    def createClient(self, more_args=None):
        return createClient(self.login, self.password, more_args=more_args)

    def createClientWithCerts(self, more_args=None):
        return createClientWithCerts(self.login, self.password, more_args=more_args)

    def __str__(self):
        return "%s:%s:%u:%u" % (self.login, self.password, self.uid, self.gid)

class PlaintextUserDB:
    def __init__(self):
        self.users = []

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

        self.basedir = mkdtemp()
        self.filename = path_join(self.basedir, "users.nufw")
        output = open(self.filename, 'w')
        output.write(text)
        output.close()

        config["nuauth_user_check_module"] = '"plaintext"'
        config["plaintext_userfile"] = '"%s"' % self.filename

    def desinstall(self):
        if hasattr(self, 'filename'):
            if path_exists(self.filename):
                remove(self.filename)
        if hasattr(self, 'basedir'):
            if path_exists(self.basedir):
                rmdir(self.basedir)

    def __getitem__(self, key):
        return self.users[key]

USERDB = PlaintextUserDB()
USERDB.addUser( PlaintextUser("username", "password", 1, 100) )
USERDB.addUser( PlaintextUser("username2", "password2", 2, 200) )

class PlaintextAcl:
    def __init__(self):
        self.content = []

    def addAclFull(self, name, host, port, gid, decision=1, **kw):
        text = [
            "[%s]" % name,
            "decision=%s" % decision,
            "gid=%u" % gid,
            "DstIP=%s" % host,
            "DstPort=%u" % port]
        for key, value in kw.iteritems():
            text.append("%s=%s" % (key, value))
        for line in text:
            info("Create plaintext ACL: %s" % text)
        self.content.extend(text)

    def addAclPerUid(self, name, host, port, uid, decision=1, **kw):
        text = [
            "[%s]" % name,
            "decision=%s" % decision,
            "uid=%u" % uid,
            "DstIP=%s" % host,
            "DstPort=%u" % port]
        for key, value in kw.iteritems():
            text.append("%s=%s" % (key, value))
        self.content.extend(text)


    def addAcl(self, name, port, gid, decision=1, **kw):
        self.addAclFull(name, "0.0.0.0/0", port, gid, decision, **kw)

    def install(self, config):
        info("Setup Plaintext ACL")
        for line in self.content:
            info("Plaintext ACL: %s" % line)

        text = "\n".join(self.content)

        self.basedir = mkdtemp()
        self.filename = path_join(self.basedir, "acls.nufw")
        output = open(self.filename, 'w')
        output.write(text)
        output.close()

        config["plaintext_aclfile"] = '"%s"' % self.filename
        config["nuauth_acl_check_module"] = '"plaintext"'

    def desinstall(self):
        if hasattr(self, 'filename'):
            if path_exists(self.filename):
                remove(self.filename)
        if hasattr(self, 'basedir'):
            if path_exists(self.basedir):
                rmdir(self.basedir)

