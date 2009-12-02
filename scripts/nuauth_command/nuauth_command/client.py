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

from socket import socket, AF_UNIX, error
from command_dec import PROTO_VERSION, decode, Answer
from time import mktime, gmtime, sleep
import re

DISCONNECT_REGEX = re.compile("^disconnect +(.*)$")
TIMEOUT = 30

class NuauthError(Exception):
    pass

class NuauthSocket:
    def __init__(self, filename):
        self.socket = socket(AF_UNIX)
        self.socket.connect(filename)
        self.socket.setblocking(0)

    def recv(self, timeout=TIMEOUT):
        SIZE = 4096
        alldata = []
        data = ""
        start_time = mktime(gmtime())
        while len(data) == SIZE or len(alldata) == 0:
            try:
                data = self.socket.recv(SIZE)
            except error, err:
                code = err[0]
                if code == 11:
                    data = ''
                elif code == 104:
                    err = "lost connection"
                else:
                    return (str(err), None)

            if not data and timeout and (mktime(gmtime()) - start_time) > timeout:
                break
            if data:
                alldata.append(data)
            else:
                sleep(0.1)

        data = "".join(alldata)

        if data == '':
            return ("no data", None)
        return (None, data)

    def send(self, data):
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
                err = "Server is not running (UNIX socket: %s)" % self.socket_filename
            raise NuauthError("Connection error: %s" % err)

        # Send client version
        err = self.socket.send(PROTO_VERSION)
        if err:
            raise NuauthError("Unable to send client version: %s" % err)

        # Read client version
        err, version = self.socket.recv()
        if err:
            raise NuauthError("Unable to read server version: %s" % err)

        # Check versions
        if version != PROTO_VERSION:
            raise NuauthError("Server version %r != client version %r: please upgrade." % (
                version, PROTO_VERSION))

    def disconnectPattern(self, pattern):
        # Command "disconnect haypo"
        users = self._send_command('users')
        total = 0
        userregex = re.compile(pattern)
        for user in users.content:
            match = userregex.match(user.name)
            if match:
                self._send_command('disconnect %s' % user.socket)
                total += 1
        value = Answer(True, total)
        return value

    def pythonCommand(self, command):
        match = DISCONNECT_REGEX.match(command)
        if not match:
            return None
        what = match.group(1)
        if what == 'all':
            return None
        try:
            # Exclude "disconnect 42"
            uid = int(what)
            return None
        except ValueError:
            pass
        return self.disconnectPattern(what)

    def execute(self, command):
        try:
            result = self.pythonCommand(command)
            if result is not None:
                return result
            return self._send_command(command)
        except NuauthError, err:
            self.reconnect()
            return self._send_command(command)

    def _send_command(self, command):
        # Send command
        err = self.socket.send(command)
        if err:
            raise NuauthError("send() error: %s" % err)

        if command == "quit":
            return None

        # Read answer
        err, data = self.socket.recv()
        if err:
            raise NuauthError("recv() error: %s" % err)
        value = decode(data)
        return value

    def reconnect(self):
        self.socket = None
        self.connect()

