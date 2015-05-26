from errno import EINVAL, ESRCH

from rpython.translator.sandbox.sandlib import SandboxedProc

class PidProc(SandboxedProc):
    def __init__(self, p_table=None, *args, **kwargs):
        self.p_table = p_table
        super(PidProc, self).__init__(*args, **kwargs)

    def do_ll_os__ll_os_getpid(self):
        if self.p_table is None:
            return 0
        for pid, process in self.p_table:
            if self is process:
                return pid
        raise RuntimeError("Process is not a member of its own process table")

    def do_ll_os__ll_os_kill(self, pid, sig):
        if sig != 9:
            return -EINVAL

        if self.p_table is None:
            if pid == 0:
                self.kill()
                return 0
            else:
                return -ESRCH

        if pid not in self.p_table:
            return -ESRCH
        self.p_table[pid].kill()
        return 0

__all__ = ["PidProc"]
