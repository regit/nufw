from subprocess import call
from logging import warning
from common import IPTABLE_QUEUE

class Iptables:
    def __init__(self):
        self.dirty = True
        self.flush()

    def __del__(self):
        self.flush()

    def _run(self, *args):
        args = ["/sbin/iptables"] + list(args)
        exitcode = call(args)
        if exitcode:
            command = " ".join(args)
            raise RuntimeError('Iptables error: unable to run command "%s" (error %s)'
                % (command, exitcode))

    def filterTcp(self, port, table="OUTPUT"):
        args = "-A %s -j %s -p tcp --dport %u -m state --state new" \
            % (table, IPTABLE_QUEUE, port)
        args = args.split()
        warning("iptables %s" % " ".join(args))
        self._run(*args)
        self.dirty = True

    def flush(self):
        if not self.dirty:
            return
        warning("iptables [flush]")
        self._run("-X")
        self._run("-F")
        self.dirty = False

