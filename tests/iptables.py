from subprocess import call
from logging import warning
from config import IPTABLE_QUEUE

_iptables_dirty = True

class Iptables:
    def __init__(self):
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
        global _iptables_dirty
        args = "-A %s -j %s -p tcp --dport %u -m state --state new" \
            % (table, IPTABLE_QUEUE, port)
        args = args.split()
        warning("iptables %s" % " ".join(args))
        self._run(*args)
        _iptables_dirty = True

    def flush(self):
        global _iptables_dirty
        if not _iptables_dirty:
            return
        warning("iptables [flush]")
        self._run("-X")
        self._run("-F")
        _iptables_dirty = False

