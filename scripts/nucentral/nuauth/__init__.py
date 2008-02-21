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
            # Create and connect client
            self.client = Client(self.socket_filename)
            try:
                self.client.connect()
            except NuauthError, err:
                self.client = None
                print "[!] %s" % err
                raise

        # Execute command and convert answer to string
        answer = self.client.execute(command)
        return str(answer.content)

    def sync_help(self):
        """Get nuauth help"""
        return self._command("help")

    def sync_version(self):
        """Get nuauth version string"""
        return self._command("version")

    def sync_uptime(self):
        """Get nuauth uptime"""
        return self._command("uptime")

    def sync_users(self):
        """Get the list of connected NuFW users"""
        return self._command("users")

    def sync_firewalls(self):
        """Get the list of connected firewalls"""
        return self._command("firewalls")

    def sync_packets_count(self):
        """Get number of decision waiting packets"""
        return self._command("packets count")

    def sync_refresh_cache(self):
        """Ask server to refresh all caches"""
        return self._command("refresh cache")

    def sync_disconnect(self, user_id):
        """Disconnect specified user"""
        return self._command("disconnect %s" % user_id)

    def sync_disconnect_all(self):
        """Disconnect all users"""
        return self._command("disconnect all")

    def sync_reload(self):
        """Reload server configuration"""
        return self._command("reload")

    def sync_display_debug_level(self):
        """Display debug level"""
        return self._command("display debug_level")

    def sync_display_debug_areas(self):
        """Display debug areas"""
        return self._command("display debug_areas")

    def sync_debug_level(self, areas):
        """Set debug level"""
        return self._command("debug_level %s" % areas)

    def sync_debug_areas(self, areas):
        """Set debug areas"""
        return self._command("debug_areas %s" % areas)

