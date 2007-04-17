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
from command_dec import PROTO_VERSION, decode, Answer
import re
import readline

COMMANDS_COMPLETION = ("version", "users", "refresh cache",
    "disconnect ", "uptime", "reload", "help", "quit",
    "display debug_level", "display debug_areas", "debug_level",
    "debug_areas", "firewalls")
COMMANDS_REGEX = re.compile(
    "^(?:version|users|firewalls|refresh cache|nupik!|display debug_(?:level|areas)|"
    "debug_level [0-9]+|debug_areas [0-9]+|"
    "disconnect (?:[0-9]+|all)|uptime|reload|help|quit)$")

class Completer:
    def __init__(self, words):
        self.words = words
        self.generator = None

    def complete(self, text):
        for word in self.words:
            if word.startswith(text):
                yield word

    def __call__(self, text, state):
        if state == 0:
            self.generator = self.complete(text)
        try:
            return self.generator.next()
        except StopIteration:
            return None
        return None

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

    def connect(self, verbose=True):
        try:
            self.socket = NuauthSocket(self.socket_filename)
        except error, err:
            if verbose:
                code = err[0]
                if code == 111:
                    err = "Server is not running"
                print "[!] Connection error: %s" % err
            return False

        # Send client version
        err = self.socket.send(PROTO_VERSION)
        if err:
            print "[!] Unable to send client version: %s" % err
            return False

        # Read client version
        err, version = self.socket.recv()
        if err:
            print "[!] Unable to read server version: %s" % err
            return False

        # Check versions
        if version != PROTO_VERSION:
            print "[!] Server version %r != client version %r: please upgrade." % (
                version, PROTO_VERSION)
            return False
        if verbose:
            print "[+] Connected"
        return True

    def execute(self, command):
        err, result = self._send_command(command)
        if err:
            ok = self.reconnect()
            if ok:
                err, result = self._send_command(command)
        if err:
            print "[!] execute(%r) error: %s" % (command, err)
            return False, None
        return True, result

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

        # Print answer
        if value.__class__ != Answer:
            print "[!] invalid answer format: %r" % answer
        if not value.ok:
            err = value.content
            print "[!] Error: %s" % err
            return "", None
        value = value.content
        if isinstance(value, list):
            for item in value:
                print str(item)
            print "(list: %s items)" % len(value)
        else:
            print str(value)
        return "", value

    def mainLoop(self):
        if not self.execute("version"):
            return
        if not self.execute("uptime"):
            return
        print
        readline.set_completer(Completer(COMMANDS_COMPLETION))
        readline.set_completer_delims(";")
        readline.parse_and_bind('tab: complete')
        while True:
            # Read command from user
            try:
                command = raw_input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                # CTRL+C or CTRL+D
                print
                print "[!] Interrupted: quit"
                command = "quit"
            if command == '':
                continue

            # Send command
            if COMMANDS_REGEX.match(command):
                ok, result = self.execute(command)
                if not ok or command == "quit":
                    return
            else:
                print "[!] Unknown command: %s\n\t(try 'help' to have a list of commands)" % command
            print

    def reconnect(self):
        del self.socket
        ok = self.connect(False)
        if ok:
            print "[+] Server restart: reconnect"
        return ok

    def run(self):
        try:
            err = self.mainLoop()
        except KeyboardInterrupt:
            print "[!] Interrupted"
            err = None
        if err:
            print err
        print "[+] Quit command client"

