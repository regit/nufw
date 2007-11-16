from config import CONF_DIR
from common import createClient
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
USERDB.addUser( PlaintextUser("username", "password", 42, 42) )
USERDB.addUser( PlaintextUser("username2", "password2", 43, 43) )

class PlaintextAcl:
    def __init__(self):
        self.content = []

    def addAclFull(self, name, host, port, gid, decision=1, **kw):
        text = [
            "[%s]" % name,
            "decision=%s" % decision,
            "gid=%u" % gid,
            "proto=6",
            "SrcIP=0.0.0.0/0",
            "SrcPort=1024-65535",
            "DstIP=%s" % host, 
            "DstPort=%u" % port]
        for key, value in kw.iteritems():
            text.append("%s=%s" % (key, value))
        self.content.extend(text)

    def addAclPerUid(self, name, host, port, uid, decision=1, **kw):
        text = [
            "[%s]" % name,
            "decision=%s" % decision,
            "uid=%u" % uid,
            "proto=6",
            "SrcIP=0.0.0.0/0",
            "SrcPort=1024-65535",
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

class Period:
    def __init__(self, name, desc="", duration=None, days_start=None, days_end=None, hours_start=None, hours_end=None):
        self.name = name
	self.desc = desc
        self.duration = duration
        self.days_start = days_start
        self.days_end = days_end
        self.hours_start = hours_start
        self.hours_end = hours_end

    def xml(self):
        rule = '<period name="%s" desc="%s">\n<perioditem>\n' % (self.name, self.desc)
        if self.duration:
            rule += '<duration length="%u"/>\n' % self.duration

        if self.days_start and self.days_end:
            rule += '<days start="%u" end="%u"/>\n' % self.days_start, self.days_end

        if self.hours_start and self.hours_end:
            rule += '<hours start="%u" end="%u"/>\n' % self.days_start, self.days_end

        rule += '</perioditem>\n</period>\n'
        return rule


class PlainPeriodXML:
    def __init__(self):
        self.periods = []

    def addPeriod(self, period):
        self.periods.append(period)

    def install(self, config):
        info("Setup periods.xml file")
    	self.basedir = mkdtemp()
        self.filename = path_join(self.basedir, "periods.xml")

        output = open(self.filename, 'w')
	output.write('<?xml version="1.0"?>\n<periods>\n')

        for period in self.periods:
            output.write(period.xml())

        output.write('</periods>\n')
        output.close()

        config["nuauth_periods_module"]= '"xml_defs"'
        config["xml_defs_periodfile"] = '"%s"' % self.filename

    def desinstall(self):
    	if hasattr(self, 'filename'):
	    if path_exists(self.filename):
	        remove(self.filename)
	if hasattr(self, 'basedir'):
	    if path_exists(self.basedir):
	        rmdir(self.basedir)


