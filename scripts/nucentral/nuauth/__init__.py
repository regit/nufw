"""
Copyright(C) 2008 INL
Written by Victor Stinner <victor.stinner AT inl.fr>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

$Id$
"""

from nucentral import Component
from nuauth_command import NuauthError, Client

class Nuauth(Component):
    NAME = "nuauth"

    def init(self, core):
        self.socket_filename = core.conf_get_var_or_default("nuauth", "socket", "/var/run/nuauth/nuauth-command.socket")
        self.client = None

    def getClient(self):
        return self.client

    def _command(self, command):
        if not self.client:
            self.client = Client(self.socket_filename)
            try:
                self.client.connect()
            except NuauthError, err:
                self.client = None
                print "[!] %s" % err
                raise

        answer = self.client.execute("version")
        return answer.content

    def sync_version(self):
        """
        Get nuauth version
        """
        return self._command("version")

