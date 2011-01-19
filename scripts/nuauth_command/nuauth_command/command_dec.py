import struct
import datetime
import IPy

PROTO_VERSION = "NuFW 0.1"

class Message:
    def __str__(self):
        raise NotImplementedError()

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, str(self))

class Answer(Message):
    def __init__(self, ok, content):
        self.ok = ok
        self.content = content

    def __str__(self):
        return "ok=%s content=%r" % (self.ok, self.content)

class Uptime(Message):
    def __init__(self, start, diff):
        self.start = start
        self.diff = datetime.timedelta(seconds=diff)

    def __str__(self):
        return "Uptime: %s since %s" % (self.diff, self.start)

class User(Message):
    def __init__(self, client_version, socket, name, addr, sport, uid, groups,
    connect_timestamp, uptime, expire,
    sysname, release, version, activated, rx, error, spoofed, hello):
        self.client_version = client_version
        self.socket = socket
        self.name = name
        self.addr = addr
        self.sport = sport
        self.uid = uid
        self.groups = groups
        self.connect_timestamp = connect_timestamp
        self.uptime = datetime.timedelta(seconds=uptime)
        if expire < 0:
            self.expire = None
        else:
            self.expire = datetime.timedelta(seconds=expire)
        self.sysname = sysname
        self.release = release
        self.version = version
        self.activated = activated
        self.rx = rx
        self.error = error
        self.spoofed = spoofed
        self.hello = hello

    def __str__(self):
        addr = self.addr.strCompressed()
        groups = ", ".join([ str(group) for group in self.groups])
        if self.expire:
            expire = ", %s" % self.expire
        else:
            expire = ""
        return "#%s: %r at %s (port %s) %s since %s\n   id: %s, groups: %s%s\n   %s %s (%s)\n   rx: %s, err: %s, hello: %s, spoofed: %s" % (
            self.socket, self.name, addr,
            self.sport, self.uptime, self.connect_timestamp,
            self.uid, groups, expire,
            self.sysname, self.release, self.version,
            self.rx, self.error, self.hello, self.spoofed)

class NuFW:
    def __init__(self, version, socket, peername, connect_timestamp, uptime, usage, alive):
        self.version = version
        self.socket = socket
        self.peername = peername
        self.connect_timestamp = connect_timestamp
        self.uptime = datetime.timedelta(seconds=uptime)
        self.usage = usage
        self.alive = alive

    def __str__(self):
        addr = self.peername.strCompressed()
        return "#%s: nufw at %s, %s since %s (usage=%s, alive=%s)" % (
            self.socket, addr, self.uptime, self.connect_timestamp,
            self.usage, self.alive)

class Decoder:
    def __init__(self, data):
        self.data = data
        self.index = 0
        self.end = len(data)

    def decode(self, maxlen=None, check_end=False):
        oldend = self.end
        if maxlen is not None:
            self.end = maxlen
        bytecode = self.read("c")

        try:
            decoder = self.DECODER[bytecode]
        except KeyError, err:
            raise ValueError("decode() error: invalid bytecode (%r)" % bytecode)

        try:
            value = decoder(self)
        except (struct.error, KeyError), err:
            raise ValueError("decode() error: %s" % err)
        if check_end and self.index != self.end:
            raise IndexError("Data at the end: %r" % self.data[self.index:self.end])
        self.end = oldend
        return value

    def readMany(self, format):
        size = struct.calcsize(format)
        if self.end < (self.index + size):
            raise IndexError("Buffer underflow")
        value = struct.unpack(format, self.data[self.index:self.index+size])
        self.index += size
        return value

    def read(self, format):
        value = self.readMany(format)
        assert len(value) == 1
        return value[0]

    def checkBytecode(self, expected):
        bytecode = self.read("c")
        if bytecode != expected:
            raise ValueError("invalid bytecode: %r instead of %r" % (
                bytecode, expected))

    # --- Low level ----

    def decode_bool(self):
        return (self.read("!B") == 1)

    def decode_int32(self):
        return self.read("!i")

    def decode_string(self):
        size = self.read("!i")
        text = self.read("!%us" % size)
        try:
            text = unicode(text, "UTF-8", "strict")
        except UnicodeDecodeError:
            text = unicode(text, "ISO-8859-1", "strict")
        return text

    def decode_ipv6(self):
        raw = self.readMany("!16B")
        value = reduce(lambda x,y: x*256+y, raw)
        return IPy.IP(value)

    def decode_timestamp(self):
        sec = self.read("!I")
        return datetime.datetime.fromtimestamp(sec)

    def decode_tuple(self):
        count = self.read("!i")
        items = []
        for index in xrange(count):
            items.append( self.decode(check_end=False) )
        return items

    # --- High level ----

    def readBool(self):
        self.checkBytecode('b')
        return self.decode_bool()

    def readInt32(self):
        self.checkBytecode('i')
        return self.decode_int32()

    def readTimestamp(self):
        self.checkBytecode('t')
        return self.decode_timestamp()

    def readString(self):
        self.checkBytecode('s')
        return self.decode_string()

    def readIPv6(self):
        self.checkBytecode('p')
        return self.decode_ipv6()

    def readTuple(self):
        self.checkBytecode('(')
        return self.decode_tuple()

    def decode_answer(self):
        size = self.readInt32()
        ok = self.readInt32()
        content = self.decode(self.index + size)
        return Answer(ok == 1, content)

    def decode_uptime(self):
        index = self.index
        start = self.readTimestamp()
        diff = self.readInt32()
        return Uptime(start, diff)

    def decode_user(self):
        index = self.index
        version = self.readInt32()
        socket = self.readInt32()
        name = self.readString()
        addr = self.readIPv6()
        sport = self.readInt32()
        uid = self.readInt32()
        groups = self.readTuple()
        timestamp = self.readTimestamp()
        uptime = self.readInt32()
        expire = self.readInt32()
        sysname = self.readString()
        release = self.readString()
        version = self.readString()
        activated = self.readBool()
        rx = self.readInt32()
        hello = self.readInt32()
        spoofed = self.readInt32()
        error = self.readInt32()
        return User(version, socket, name, addr, sport,
            uid, groups, timestamp, uptime, expire,
            sysname, release, version, activated, rx, error, spoofed, hello)

    def decode_nufw(self):
        index = self.index
        version = self.readInt32()
        socket = self.readInt32()
        peername = self.readIPv6()
        timestamp = self.readTimestamp()
        uptime = self.readInt32()
        usage = self.readInt32()
        alive = self.readBool()
        return NuFW(version, socket, peername, timestamp, uptime, usage, alive)

    DECODER = {
        'b': decode_bool,
        'i': decode_int32,
        's': decode_string,
        '(': decode_tuple,
        'p': decode_ipv6,
        't': decode_timestamp,

        'a': decode_answer,
        'U': decode_uptime,
        'u': decode_user,
        'w': decode_nufw,
    }

def decode(data):
   return Decoder(data).decode()

