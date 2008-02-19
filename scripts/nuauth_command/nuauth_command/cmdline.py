import readline
from nuauth_command import Client
import re
from command_dec import Answer

COMMANDS_COMPLETION = ("version", "users", "refresh cache",
    "disconnect ", "uptime", "reload", "help", "quit",
    "display debug_level", "display debug_areas", "debug_level",
    "debug_areas", "firewalls", "packets count")

COMMANDS_REGEX = re.compile(
    "^(?:version|users|firewalls|refresh cache|nupik!|display debug_(?:level|areas)|"
    "debug_level [0-9]+|debug_areas [0-9]+|"
    "disconnect (?:[0-9]+|all)|uptime|reload|help|quit|packets count)$")

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

def displayAnswer(value):
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

class CommandLineClient(Client):
    def mainLoop(self):
        # Display version and uptime
        version = self.execute("version")
        uptime = self.execute("uptime")
        displayAnswer(version)
        displayAnswer(uptime)
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
                try:
                    value = self.execute(command)
                except NuauthError, err:
                    print "[!] %s" % err
                    return
                if command == "quit":
                    return
                displayAnswer(value)
            else:
                print "[!] Unknown command: %s\n\t(try 'help' to have a list of commands)" % command
            print

    def run(self):
        try:
            err = self.mainLoop()
        except KeyboardInterrupt:
            print "[!] Interrupted"
            err = None
        if err:
            print err
        print "[+] Quit command client"

