#!/usr/bin/python

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
from sys import exit
from command_dec import decode, Answer

class NuauthSocket:
    def __init__(self, filename):
        self.socket = socket(AF_UNIX)
        self.socket.connect(filename)

    def recv(self):
        size = 10
        data = self.socket.recv(size)
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
    SOCKET_FILENAME = "/tmp/nuauth-command.socket"

    def __init__(self):
        self.debug = True
        self.socket = None

    def connect(self, verbose=True):
        try:
            self.socket = NuauthSocket(self.SOCKET_FILENAME)
        except error, err:
            if verbose:
                print "[!] Connection error: %s" % err
            return False
        if verbose:
            print "[+] Connected"
        return True

    def _execute(self, command):
        # Send command
        err = self.socket.send(command)
        if err:
            print "[!] send() error: %s" % err
            return False

        if command == "quit":
            return True

        # Read answer
        err, data = self.socket.recv()
        if err:
            print "[!] recv() error: %s" % err
            return False
        value = decode(data)

        # Print answer
        if value.__class__ != Answer:
            print "[!] invalid answer format: %r" % answer
        if not value.ok:
            print "[!] Error: %s" % value.content
        else:
            print value.content
        return True

    def execute(self, command):
        ok = self._execute(command)
        if not ok:
            ok = self.reconnect()
            if ok:
                ok = self._execute(command)
        if not ok:
            print "[!] execute(%r) error" % command
            return False
        return True

    def mainLoop(self):
        if not self.execute("version"):
            return
        if not self.execute("uptime"):
            return
        while True:
            # Read command from user
            try:
                command = raw_input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                # CTRL+C or CTRL+D
                print "quit"
                command = "quit"
            if command == '':
                continue

            # Send command
            if not self.execute(command):
                return
            if command == "quit":
                return

    def reconnect(self):
        del self.socket
        ok = self.connect(False)
        if ok:
            print "[+] Server restart: reconnect"
        return ok

    def run(self):
        err = self.mainLoop()
        if err:
            print err
        print "[+] Quit"

def main():
    client = Client()
    if not client.connect():
        exit(1)
    client.run()

if __name__ == "__main__":
    main()

