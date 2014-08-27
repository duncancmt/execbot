def load_constants():
    import ffi
    constants = ['MAP_PRIVATE', 'MAP_FIXED', 'MAP_ANONYMOUS']
    cdef_lines = ""
    for constant in constants:
        cdef_lines += "#define %s ...\n" % constant
    ffi.cdef(cdef_lines)
    C = ffi.verify("""
#include <sys/mman.h>
""")
    for constant in constants:
        globals()[constant] = getattr(C, constant)
load_constants()

from seccomp import *
from errno import *
from prctl import *

# not needed becaused the prisoner will jail itself
#+ SYSCALL('execve', ALLOW)
#+ SYSCALL('rt_sigreturn', ALLOW)

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
                             ARG(0),
                           + JEQ_IMM(prctl.PR_SET_NO_NEW_PRIVS,
                                       ARG(1),
                                     + JEQ_IMM(1,
                                               ALLOW))
                           + DENY_KILL)
                 # additions that make me sad
                 + SYSCALL('uname', ALLOW)
                 + SYSCALL('access', DENY_ERROR(ENOENT))
                 + SYSCALL('mprotect',
                             ARG(2)
                           + JSET_IMM(PROT_WRITE,
                                      DENY_KILL)
                           + ALLOW)
                 # catchall
                 + DENY_KILL)

__all__ = ['filter']
