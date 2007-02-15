#!/usr/bin/python

from socket import socket, AF_UNIX

class Client:
    SOCKET_FILENAME = "/tmp/nuauth-command.socket"

    def __init__(self):
        self.socket = socket(AF_UNIX)
        self.socket.connect(self.SOCKET_FILENAME)
        print "Connected"

def main():
    client = Client()

if __name__ == "__main__":
    main()

