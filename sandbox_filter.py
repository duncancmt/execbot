def load_constants():
    from cffi import FFI
    constants = ['MAP_PRIVATE', 'MAP_FIXED', 'MAP_ANONYMOUS']
    cdef_lines = ""
    for constant in constants:
        cdef_lines += "#define %s ...\n" % constant
    ffi = FFI()
    ffi.cdef(cdef_lines)
    C = ffi.verify("""
#include <sys/mman.h>
""")
    for constant in constants:
        globals()[constant] = getattr(C, constant)
load_constants()

from errno import *
from seccomp.bpf import *
from seccomp.seccomp import *
from seccomp.prctl import *

filter = compile(  VALIDATE_ARCH
                 + LOAD_SYSCALL_NR
                 # syscalls allowed by normal seccomp
                 + SYSCALL('read', ALLOW)
                 + SYSCALL('write', ALLOW)
                 + SYSCALL('exit', ALLOW)
                 + SYSCALL('exit_group', ALLOW)
                 # reasonable additions
                 + SYSCALL('brk', ALLOW)
                 + SYSCALL('mmap2', # only allow the mappings malloc makes
                             ARG(3)
                           + JEQ_IMM(MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,
                                     ALLOW)
                           + DENY_KILL)
                 + SYSCALL('munmap', ALLOW)
                 + SYSCALL('close', ALLOW)
                 + SYSCALL('prctl', # only allow prctl(PR_SET_NO_NEW_PRIVS, 1)
                             ARG(0)
                           + JEQ_IMM(PR_SET_NO_NEW_PRIVS,
                                       ARG(1)
                                     + JEQ_IMM(1,
                                               ALLOW))
                           + DENY_KILL)
                 # additions that make me sad
                 + SYSCALL('uname', ALLOW)
                 + SYSCALL('access', DENY_ERROR(ENOENT))
                 # catchall
                 + DENY_KILL)

__all__ = ['filter']
