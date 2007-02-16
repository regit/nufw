#!/usr/bin/python

from socket import socket, AF_UNIX, error
from sys import exit

class Client:
    SOCKET_FILENAME = "/tmp/nuauth-command.socket"

    def connect(self):
        try:
            self.socket = socket(AF_UNIX)
            self.socket.connect(self.SOCKET_FILENAME)
        except error, err:
            print "[!] Connection error: %s" % err
            return False
        print "[+] Connected"
        return True

    def run(self):
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
            try:
                self.socket.send(command)
            except error, err:
                code = err[0]
                if code == 32:
                    print "[!] lost connection with server"
                else:
                    print "[!] send() error: %s" % err
                break

            # Leave on "quit" command
            if command == "quit":
                break

            # Wait answer
            data = self.socket.recv(10)
            if data == '':
                print "[!] lost connection with server"
                break
            print "Data: %r" % data

        # Quit
        self.socket.close()
        print "[+] Quit"

def main():
    client = Client()
    if not client.connect():
        exit(1)
    client.run()

if __name__ == "__main__":
    main()

