import sys, os, subprocess
from pid import PidProc
from rpython.translator.sandbox.sandlib import VirtualizedSandboxedProc
from sandbox.pipe import PipeProc
from rpython.translator.sandbox.vfs import Dir, RealDir, RealFile
LIB_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.__file__)))

def go_to_jail(chroot_path, jail_uid, jail_gid):
    # chroot
    os.chdir(chroot_path)
    os.chroot(chroot_path)

    # drop privs
    os.setgroups([])
    os.setgid(jail_gid)
    os.setuid(jail_uid)

class JailedProc(PidProc, VirtualizedSandboxedProc, PipeProc):
    def __init__(self, sandbox_args, executable, tmpdir=None, chroot=None, procdir=None, p_table=None):
        if '-S' not in sandbox_args:
            sandbox_args = ('-S',) + tuple(sandbox_args)

        self.executable = os.path.abspath(executable)
        self.tmpdir = os.path.abspath(tmpdir) if tmpdir is not None else None
        self.chroot = os.path.abspath(chroot) if chroot is not None else None
        self.procdir = procdir
        self.p_table = p_table
        self.virtual_root = self.build_virtual_root()
        self.open_fds = {}

        self.popen = subprocess.Popen(sandbox_args, executable=self.executable,
                                      bufsize=-1,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      preexec_fn=go_to_jail,
                                      close_fds=True,
                                      cwd=(self.chroot if self.chroot is not None else '.'),
                                      env={})
        self.popenlock = None
        self.currenttimeout = None
        self.currentlyidlefrom = None

    def build_virtual_root(self):
        exclude = ['.pyc', '.pyo']
        if self.tmpdir is None:
            tmpdirnode = Dir({})
        else:
            tmpdirnode = RealDir(self.tmpdir, exclude=exclude)
        libroot = str(LIB_ROOT)

        return Dir({
            'usr': Dir({
                'include' : RealDir(os.path.join(os.sep, 'usr', 'include'),
                                   exclude=exclude)
                }),
            'bin': Dir({
                'pypy-c': RealFile(self.executable),
                'lib-python': RealDir(os.path.join(libroot, 'lib-python'),
                                      exclude=exclude),
                'lib_pypy': RealDir(os.path.join(libroot, 'lib_pypy'),
                                      exclude=exclude),
                }),
             'tmp': tmpdirnode,
             'proc': procdirnode if procdirnode is not None else Dir({}),
             })

__all__ = ["JailedProc"]
