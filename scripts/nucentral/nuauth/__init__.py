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

def timedeltaSeconds(delta):
    return delta.seconds + delta.days * 3600 * 24

class Nuauth(Component):
    NAME = "nuauth"
    VERSION = "1.0"
    API_VERSION = 1

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
                raise

        # Execute command and convert answer to string
        result = self.client.execute(command)
        result = result.content
        return result

    def service_version(self, context):
        """Get nuauth version string"""
        return self._command("version")

    def service_uptime(self, context):
        """Get nuauth uptime"""
        uptime = self._command("uptime")
        return {
            'start': str(uptime.start),
            'seconds': timedeltaSeconds(uptime.diff),
        }

    def service_users(self, context):
        """Get the list of connected NuFW users"""
        users = []
        for user in self._command("users"):
            users.append({
                'name': user.name,
                'uid': user.uid,
            })
        return users

    def service_firewalls(self, context):
        """Get the list of connected firewalls"""
        return self._command("firewalls")

    def service_packets_count(self, context):
        """Get number of decision waiting packets"""
        return self._command("packets count")

    def service_refresh_cache(self, context):
        """Ask server to refresh all caches"""
        return self._command("refresh cache")

    def service_disconnect(self, context, user_id):
        """Disconnect specified user"""
        return self._command("disconnect %s" % user_id)

    def service_disconnect_all(self, context):
        """Disconnect all users"""
        return self._command("disconnect all")

    def service_reload(self, context):
        """Reload server configuration"""
        return self._command("reload")

    def service_display_debug_level(self, context):
        """Display debug level"""
        return self._command("display debug_level")

    def service_display_debug_areas(self, context):
        """Display debug areas"""
        return self._command("display debug_areas")

    def service_debug_level(self, context, areas):
        """Set debug level"""
        return self._command("debug_level %s" % areas)

    def service_debug_areas(self, context, areas):
        """Set debug areas"""
        return self._command("debug_areas %s" % areas)

