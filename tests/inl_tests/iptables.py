"""
Send commands to Netfilter using iptables program
"""
from process import callProcess
from logging import warning
from inl_tests.config import IPTABLES_PROG, IPTABLES_QUEUE

_iptables_dirty = True
HAS_NAT = False

class Iptables:
    def __init__(self):
        self.flush()

    def __del__(self):
        self.flush()

    def command(self, args):
        global _iptables_dirty
        _iptables_dirty = True
        command_list = [IPTABLES_PROG] + args.split()
        command = "%s %s" % (IPTABLES_PROG, args)
        warning(command)
        exitcode = callProcess(command_list)
        if exitcode:
            raise RuntimeError('Iptables error: unable to run: %s (error %s)'
                % (command, exitcode))

    def filterTcp(self, port, table="OUTPUT"):
        global _iptables_dirty
        args = "-A %s -p tcp --dport %u -m state --state new -j %s" \
            % (table, port, IPTABLES_QUEUE)
        self.command(args)

    def flush(self):
        global _iptables_dirty
        if not _iptables_dirty:
            return
        self.command("-X")
        self.command("-F")
        if HAS_NAT:
            self.command("-F -t nat")
        self.command("-F -t mangle")
        _iptables_dirty = False

