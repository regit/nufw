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

class Client:
    SOCKET_FILENAME = "/tmp/nuauth-command.socket"

    def connect(self, verbose=True):
        try:
            self.socket = socket(AF_UNIX)
            self.socket.connect(self.SOCKET_FILENAME)
        except error, err:
            if verbose:
                print "[!] Connection error: %s" % err
            return False
        if verbose:
            print "[+] Connected"
        return True

    def readAnswer(self):
        size = 10
        data = self.socket.recv(size)
        if data == '':
            if self.reconnect():
                return
        if data == '':
            return "[!] lost connection with server"
        if len(data) == size:
            alldata = [data]
            while len(data) == size:
                data = self.socket.recv(size)
                if not data:
                    break
                alldata.append(data)
            data = "".join(alldata)
        if data != "ok":
            print data
        return ""

    def send(self, data):
        assert data
        err = ""
        try:
            self.socket.send(data)
        except error, err:
            code = err[0]
            if code == 32:
                err = "[!] lost connection with server"
            else:
                err = "[!] send() error: %s" % err
        if err and self.reconnect():
            try:
                self.socket.send(data)
                err = ''
            except error, err:
                pass
        return err

    def mainLoop(self):
        while True:
            # Read command from user
            try:
                command = raw_input("command? ").strip()
            except (EOFError, KeyboardInterrupt):
                # CTRL+C or CTRL+D
                print "quit"
                command = "quit"
            if command == '':
                continue

            # Send command
            err = self.send(command)
            if err:
                return err

            # Leave on "quit" command
            if command == "quit":
                return

            # Wait answer
            err = self.readAnswer()
            if err:
                print err
                return

    def reconnect(self):
        self.socket.close()
        ok = self.connect(False)
        if ok:
            print "[+] Server restart: reconnect"
        return ok

    def run(self):
        self.mainLoop()
        print "[+] Quit"

def main():
    client = Client()
    if not client.connect():
        exit(1)
    client.run()

if __name__ == "__main__":
    main()

