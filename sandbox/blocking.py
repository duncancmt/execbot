import time
from rpython.translator.sandbox.sandlib import SandboxedProc

BLOCK = object()
CONTINUE = object()

class can_block(object):
    def __init__(self, f):
        self.f = f
        self.cont = None

    def __call__(self, *args, **kwargs):
        if self.cont is None:
            self.cont = self.f(*args, **kwargs)
            return self(CONTINUE)
        else:
            if len(args) != 1 \
                or len(kwargs) != 0 \
                or args[0] is not CONTINUE:
                raise ValueError("Cannot supply new arguments while a syscall is pending")
            ret = self.cont.next()
            if ret is None:
                return BLOCK
            else:
                self.cont = None
                return ret

class BlockingProc(SandboxedProc):
    def handle_message(self, fnname, *args):
        if '__' in fnname:
            raise ValueError("unsafe fnname")
        try:
            handler = getattr(self, 'do_' + fnname.replace('.', '__'))
        except AttributeError:
            raise RuntimeError("no handler for this function")
        resulttype = getattr(handler, 'resulttype', None)
        answer = handler(*args)
        while answer is BLOCK:
            self.enter_idle()
            try:
                time.sleep(1)
            finally:
                self.leave_idle()
            answer = handler(CONTINUE)
        return answer, resulttype

__all__ = ["can_block", "BlockingProc"]
