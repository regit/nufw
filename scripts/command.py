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

    def __init__(self):
        self.debug = True

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
                return True
        if data == '':
            print "[!] lost connection with server"
            return False
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
                        print "[!] recv() error: %s" % err
                        return False
                if not data:
                    break
                alldata.append(data)
            data = "".join(alldata)
            self.socket.setblocking(1)
        if data != "ok":
            print data.strip()
        return True

    def send(self, data, retry=True):
        err = ""
        try:
            self.socket.send(data)
        except error, err:
            code = err[0]
            if code == 32:
                err = "[!] lost connection with server"
            else:
                err = "[!] send() error: %s" % err
        if err and retry and self.reconnect():
            try:
                self.socket.send(data)
                err = ''
            except error, err:
                pass
        if err:
            print err
            return False
        return True

    def mainLoop(self):
        if not(self.send("version") and self.readAnswer()):
            return "[!] Error on 'version' command"
        if not(self.send("uptime") and self.readAnswer()):
            return "[!] Error on 'uptime' command"
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
            if not self.send(command, command!="quit"):
                return

            # Leave on "quit" command
            if command == "quit":
                return

            # Wait answer
            if not self.readAnswer():
                return

    def reconnect(self):
        self.socket.close()
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

