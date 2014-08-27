import sys, os, subprocess
from rpython.translator.sandbox.sandlib import SimpleIOSandboxedProc
from rpython.translator.sandbox.sandlib import VirtualizedSandboxedProc
from rpython.translator.sandbox.vfs import Dir, RealDir, RealFile
LIB_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.__file__)))

class JailedSandboxedProc(VirtualizedSandboxedProc, SimpleIOSandboxedProc):
    def __init__(self, sandbox_executable, sandbox_args, tmpdir=None, chroot=None):
        if '-S' not in self.sandbox_args:
            sandbox_args = ('-S',) + tuple(self.sandbox_args)

        self.tmpdir = os.path.abspath(tmpdir) if tmpdir is not None else None
        self.chroot = os.path.abspath(chroot) if chroot is not None else None
        self.virtual_root = self.build_virtual_root()
        self.open_fds = {}

        self.popen = subprocess.Popen(sandbox_args, executable=sandbox_executable,
                                      bufsize=-1,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      preexec_fn=self.go_to_jail
                                      close_fds=True,
                                      cwd=(self.chroot if self.chroot is not None else '.'),
                                      env={})
        self.popenlock = None
        self.currenttimeout = None
        self.currentlyidlefrom = None
                                      
                                      
    def go_to_jail(self):
        # chroot

        # drop privs
