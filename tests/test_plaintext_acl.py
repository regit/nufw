#!/usr/bin/python2.4
from unittest import TestCase, main
from common import (CONF_DIR,
    reloadNuauth, getNuauthConf,
    createClient, connectClient)
from iptables import Iptables
from os import path

ACL_FILENAME = path.join(CONF_DIR, "acls.nufw")
PORT = 5000

class TestPlaintextAcl(TestCase):
    def setUp(self):
        self.iptables = Iptables()

        # Start nuauth with new config
        self.config = getNuauthConf()
        self.config["plaintext_aclfile"] = '"%s"' % ACL_FILENAME
        self.config["nuauth_acl_check_module"] = '"plaintext"'
        self.config.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.config.desinstall()
        reloadNuauth()
        self.iptables.flush()

    def testFilter(self):
        # Prepare filtering
        self.iptables.filterTcp(PORT)

        # Connect user
        client = createClient()
        self.assert_(connectClient(client))

        # Open connection
        #--- TODO ---

        # Wait connection
        #--- TODO -------

        # Disconnect user
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

