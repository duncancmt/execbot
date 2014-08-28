from errno import *
from mmap import MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS
from seccomp.bpf import *
from seccomp.seccomp import *
from seccomp.prctl import *

# apply filter
prctl(PR_SET_SECCOMP,
      SECCOMP_MODE_FILTER,
      compile(VALIDATE_ARCH
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
              + DENY_KILL))
# prevent changing filter
prctl.prctl(prctl.PR_SET_NO_NEW_PRIVS, 1)
