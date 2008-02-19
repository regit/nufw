# Copyright(C) 2007 INL
# Written by Victor Stinner <victor.stinner@inl.fr>
#
# $Id$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

from socket import socket, AF_UNIX, error
from command_dec import PROTO_VERSION, decode

class NuauthError(Exception):
    pass

class NuauthSocket:
    def __init__(self, filename):
        self.socket = socket(AF_UNIX)
        self.socket.connect(filename)

    def recv(self):
        size = 4096
        try:
            data = self.socket.recv(size)
        except error, err:
            code = err[0]
            if code == 104:
                err = "lost connection"
            else:
                err = str(err)
            return (err, None)
        if data == '':
            return ("no data", None)
        if len(data) == size:
            self.socket.setblocking(0)
            alldata = [data]
            while len(data) == size:
                try:
                    data = self.socket.recv(size)
                except error, err:
                    code = err[0]
                    if code == 11:
                        data = ''
                    else:
                        return (str(err), None)
                if not data:
                    break
                alldata.append(data)
            self.socket.setblocking(1)
            data = "".join(alldata)
        return (None, data)

    def send(self, data, retry=True):
        err = ""
        try:
            self.socket.send(data)
        except error, err:
            code = err[0]
            if code == 32:
                return "lost connection with server"
            else:
                return str(err)
        return None

class Client:
    def __init__(self, socket_filename):
        self.debug = True
        self.socket = None
        self.socket_filename = socket_filename

    def connect(self):
        try:
            self.socket = NuauthSocket(self.socket_filename)
        except error, err:
            code = err[0]
            if code == 111:
                err = "Server is not running"
            raise NuauthError("Connection error: %s" % err)

        # Send client version
        err = self.socket.send(PROTO_VERSION)
        if err:
            raise NuauthError("Unable to send client version: %s" % err)

        # Read client version
        err, version = self.socket.recv()
        if err:
            raise Nuautherror("Unable to read server version: %s" % err)

        # Check versions
        if version != PROTO_VERSION:
            raise NuauthError("Server version %r != client version %r: please upgrade." % (
                version, PROTO_VERSION))

    def execute(self, command):
        err, result = self._send_command(command)
        if err:
            ok = self.reconnect()
            if ok:
                err, result = self._send_command(command)
        if err:
            raise NuauthError("execute(%r) error: %s" % (command, err))
        return result

    def _send_command(self, command):
        # Send command
        err = self.socket.send(command)
        if err:
            return "send() error: %s" % err, None

        if command == "quit":
            return "", None

        # Read answer
        err, data = self.socket.recv()
        if err:
            return "recv() error: %s" % err, None
        value = decode(data)
        return "", value

    def reconnect(self):
        self.socket = None
        return self.connect(False)

