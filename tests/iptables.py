from subprocess import call

class Iptables:
    def __init__(self):
        self.dirty = False
        self.flush()

    def __del__(self):
        if self.dirty:
            self.flush()

    def _run(self, *args):
        args = ["/sbin/iptables"] + list(args)
        exitcode = call(args)
        if exitcode:
            command = " ".join(args)
            raise RuntimeError('Iptables error: unable to run command "%s" (error %s)'
                % (command, exitcode))

    def filterTcp(self, port, table="OUTPUT"):
        args = "-A %s -j NFQUEUE -p tcp --dport %u -m state --state new" \
            % (table, port)
        args = args.split()
        self._run(*args)
        self.dirty = True

    def flush(self):
        self._run("-X")
        self._run("-F")
        self.dirty = False

