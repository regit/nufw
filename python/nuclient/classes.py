# Copyright(C) 2007 INL
# Written by Victor Stinner <victor.stinner@inl.fr>
#
# $Id$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
"""
NuclientError and Nuclient classes: Python object API for libnuclient
"""

from nuclient import (
    nuclient_error_p,
    nu_client_error_init, nu_client_error_destroy,
    nu_client_global_init, nu_client_global_deinit,
    nu_client_new, nu_client_delete,
    nu_client_check, nu_client_set_verbose,
    nu_client_connect,
    nu_client_strerror,
    DEFAULT_PORT)
from ctypes import byref

class NuclientError(RuntimeError):
    def __init__(self, when, error):
        message = "%s! Problem: %s" % (when, nu_client_strerror(error))
        RuntimeError.__init__(self, message)

class Nuclient:
    def __init__(self, username, password, diffie_hellman=True):
        self._init_error = False
        self._global_init = False
        self.session = None

        assert isinstance(username, unicode)
        assert isinstance(password, unicode)
        self.username = username
        self.password = password
        self.error = nuclient_error_p()

        self.init()
        self.session = nu_client_new(
            self.username.encode("utf8"), self.password.encode("utf8"),
            diffie_hellman, self.error)
        if not self.session:
            raise NuclientError("nu_client_new", self.error)

    def init(self):
        # Allocate error structure
        if not self._init_error:
            if nu_client_error_init(byref(self.error)) != 0:
                raise MemoryError("Cannot init error structure!")
            self._init_error = True

        # global libnuclient init
        if not self._global_init:
            if not nu_client_global_init(self.error):
                raise NuclientError("Unable to initiate nuclient library!", self.error)
            self._global_init = True

    def deinit(self):
        if self._global_init:
            nu_client_global_deinit()
            self._global_init = False

        if self._init_error:
            nu_client_error_destroy(self.error)
            self._init_error = False

        if self.session:
            nu_client_delete(self.session)
            self.session = None

    def __del__(self):
        self.deinit()

    def connect(self, hostname, port=None):
        if not port:
            port = str(DEFAULT_PORT)
        assert isinstance(hostname, str)
        assert isinstance(port, str)
        ok = nu_client_connect(self.session, hostname, port, self.error)
        if not ok:
            raise NuclientError("Unable to connect to %s:%s" % (hostname, service),
                self.error)

    def verbose(self, enabled):
        assert isinstance(enabled, bool)
        nu_client_set_verbose(self.session, enabled)

    def check(self):
        connected = nu_client_check(self.session, self.error)
        return (connected == 1)

__all__ = ("NuclientError", "Nuclient")

