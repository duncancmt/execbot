from errno import EINVAL, ENOSYS
from mmap import MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS

from seccomp.bpf import *
from seccomp.seccomp import *
from seccomp.prctl import *

# prevent changing filter (must be run before setting filter)
prctl(PR_SET_NO_NEW_PRIVS, 1,
      0, 0, 0)
# apply filter
prctl(PR_SET_SECCOMP,
      SECCOMP_MODE_FILTER,
      compile(
        VALIDATE_ARCH(
            LOAD_SYSCALL_NR
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
                    + DENY_ERROR(EINVAL))
          + SYSCALL('munmap', ALLOW)
          + SYSCALL('close', ALLOW)
          # catchall
          + DENY_ERROR(ENOSYS))
        + DENY_KILL),
      0, 0)
