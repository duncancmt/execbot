import os

__all__ = ['ALLOW', 'DENY_KILL', 'DENY_ERROR', 'SYSCALL', 'LO_ARG', 'HI_ARG',
           'ARG', 'LOAD_SYSCALL_NR', 'LOAD_ARCH_NR', 'VALIDATE_ARCH',
           'syscall_by_name']

def load_constants():
    import re
    global ffi

    constants = ['AUDIT_ARCH_I386', 'AUDIT_ARCH_X86_64', 'AUDIT_ARCH_ARM']
    for match in re.finditer(r"^\s*#\s*define\s+([^_][A-Z_]*)\s+([0-9bXx]+).*$",
                             open("/usr/include/linux/seccomp.h", "r").read(),
                             re.MULTILINE):
        try:
            int(match.group(2), base=0)
        except ValueError:
            pass
        else:
            constant = match.group(1)
            __all__.append(constant)
            constants.append(constant)

    syscalls_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.uname()[4] + '_syscalls.txt')
    for syscall in open(syscalls_file, 'r'):
        # we don't export the syscalls because there's too many of them, SYSCALL
        # below will automatically convert their string names, and we export
        # syscall_by_name
        constants.append('__NR_'+syscall.strip())

    from cffi import FFI
    ffi = FFI()

    cdef_lines = """
/*
struct seccomp_data {
	...;
};
*/
struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};
"""
    for constant in constants:
        cdef_lines += "#define %s ...\n" % constant
    ffi.cdef(cdef_lines)
    C = ffi.verify("""
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/unistd.h>
""")
    for constant in constants:
        globals()[constant] = getattr(C, constant)
load_constants()



import sys
from struct import calcsize

from bpf import *


ALLOW = RET_IMM(SECCOMP_RET_ALLOW)
DENY_KILL = RET_IMM(SECCOMP_RET_KILL)
def DENY_ERROR(errno):
    return RET_IMM(SECCOMP_RET_ERRNO | (errno & 0xffff))

if sys.byteorder == 'little':
    def LO_ARG(idx):
        return ffi.offsetof('struct seccomp_data', 'args') \
               + ffi.sizeof('uint64_t') * idx
elif sys.byteorder == 'big':
    def LO_ARG(idx):
        return ffi.offsetof('struct seccomp_data', 'args') \
               + ffi.sizeof('uint64_t') * idx \
               + ffi.sizeof('uint32_t')
else:
    raise RuntimeError("Unknown endianness")

# FIXME: assumes 8-bit bytes
if calcsize('l') == 4:
    HI_ARG = None
    def ARG(i):
        return LWD_IMM(LO_ARG(i))
elif calcsize('l') == 8:
    if sys.byteorder == 'little':
        def HI_ARG(idx):
            return ffi.offsetof('struct seccomp_data', 'args') \
                   + ffi.sizeof('uint64_t') * idx \
                   + ffi.sizeof('uint32_t')
    else:
        def HI_ARG(idx):
            return ffi.offsetof('struct seccomp_data', 'args') \
                   + ffi.sizeof('uint64_t') * idx
    def ARG(i):
        return   LDW_IMM(LO_ARG(i)) \
               + ST(0) \
               + LDW_IMM(HI_ARG(i)) \
               + ST(1)
else:
    raise RuntimeError("Unusable long size", calcsize('l'))


def SYSCALL(nr, jt):
    if isinstance(nr, basestring):
        if not nr.startswith('__NR_'):
            nr = '__NR_'+nr
        nr = globals()[nr]
    return JEQ_IMM(nr, jt)


LOAD_SYSCALL_NR = LDW_IMM(ffi.offsetof('struct seccomp_data', 'nr'))
LOAD_ARCH_NR = LDW_IMM(ffi.offsetof('struct seccomp_data', 'arch'))
arch = os.uname()[4]
if arch == 'i386':
    def VALIDATE_ARCH(jt):
        return   LOAD_ARCH_NR \
               + JEQ_IMM(AUDIT_ARCH_I386,
                         jt)
elif arch == 'x86_64':
    def VALIDATE_ARCH(jt):
        return   LOAD_ARCH_NR \
               + JEQ_IMM(AUDIT_ARCH_X86_64,
                         jt)
elif re.match(r'armv[0-9]+.*', arch):
    def VALIDATE_ARCH(jt):
        return   LOAD_ARCH_NR \
               + JEQ_IMM(AUDIT_ARCH_ARM,
                         jt)

def syscall_by_name(name):
    if not name.startswith('__NR_'):
        name = '__NR_'+name
    return globals()[name]
