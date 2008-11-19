from config import CONF_DIR
from config import config as test_config
from common import createClient
from os.path import join as path_join
from os.path import exists as path_exists
from os import remove
from os import rmdir
from logging import info
from IPy import IP
import ldap
import ldap.modlist
from string import split


class LDAPAcl:

    def __init__(self):
        self.acllist = []

        self.ldapuri = test_config.get('test_ldap', 'ldapuri')
        self.basedn = test_config.get('test_ldap', 'basedn')
        self.binddn = test_config.get('test_ldap', 'binddn')
        self.bindpw = test_config.get('test_ldap', 'bindpw')

        self.conn = ldap.initialize(self.ldapuri)
        try:
            self.conn.simple_bind_s(self.binddn, self.bindpw)
        except ldap.INVALID_CREDENTIALS:
            print "Invalid auth: %s/%s" % (self.binddn, self.bindpw)


    def format_acl(self, name, host, port, decision, kw):
        ldapattr = {}
        ldapattr['objectclass'] = ['NuAccessControlList']
        ldapattr['cn'] = [name]
        ldapattr['Proto'] = [str(6)]
        ldapattr['DstPortStart'] = [str(port)]
        ldapattr['DstPortEnd'] = [str(port)]
        ldapattr['Decision'] = [str(decision)]
        dip = str(IP(host).int())
        ldapattr['DstIPStart'] = [dip]
        ldapattr['DstIPEnd'] = [dip]
        ldapattr['SrcIPStart'] = [str(0)]
        ldapattr['SrcIPEnd'] = [str(pow(2,32)-1)]

        ftraduc = { 'App': 'AppName', 'log_prefix': 'description', 'outdev': 'OutDev' }
        for key, value in kw:
            if (key == 'OS'):
                osfields = [ 'OsName', 'OsRelease', 'OsVersion']
                for val in value.split(';'):
                    ldapattr[osfields.pop(0)] = val
            else:
                ldapattr[ftraduc[key]] = [str(value)]

        return ldapattr

    def addAclFull(self, name, host, port, gid, decision=1, **kw):
        ldapattr = self.format_acl(name, host, port, decision, kw.iteritems())
        ldapattr['Group'] = [ str(gid) ]
        dn = 'cn='+name+','+self.basedn
        modlist = ldap.modlist.addModlist(ldapattr)
        try:
            self.conn.add_s(dn, modlist)
        except ldap.ALREADY_EXISTS:
            self.conn.delete_s(dn) 
            self.conn.add_s(dn, modlist)
        self.acllist.append(dn)

    def addAclPerUid(self, name, host, port, uid, decision=1, **kw):
        ldapattr = self.format_acl(name, host, port, decision, kw.iteritems())
        ldapattr['User'] = [ str(uid) ]

        dn = 'cn='+name+','+self.basedn
        modlist = ldap.modlist.addModlist(ldapattr)
        try:
            self.conn.add_s(dn, modlist)
        except ldap.ALREADY_EXISTS:
            self.conn.delete_s(dn) 
            self.conn.add_s(dn, modlist)
        self.acllist.append(dn)


    def addAcl(self, name, port, gid, decision=1, **kw):
        self.addAclFull(name, "0.0.0.0/0", port, gid, decision, **kw)

    def install(self, config):
        info("Setup LDAP ACL")

        config["nuauth_acl_check_module"] = '"ldap"'
        config["ldap_acls_base_dn"] = '"'+self.basedn+'"'
        config["ldap_bind_dn"] = '"'+self.binddn+'"'
        config["ldap_bind_password"] = '"'+self.bindpw+'"'
        config["nuauth_acl_cache"] = 0

    def desinstall(self):
        # drop all inserted acls
        for dn in self.acllist:
            try:
                self.conn.delete_s(dn)
            except ldap.NO_SUCH_OBJECT:
                pass

