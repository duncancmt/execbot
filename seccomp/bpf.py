from itertools import chain

__all__ = ['ALLOW', 'DENY_KILL', 'DENY_ERROR', 'JUMP', 'LABEL', 'SYSCALL',
           'LO_ARG', 'HI_ARG',
           'JEQ', 'JNE', 'JGT', 'JLT', 'JGE', 'JLE', 'JA', 'ARG',
           'LOAD_SYSCALL_NR', 'LOAD_ARCH_NR', 'VALIDATE_ARCH',
           'syscall_by_name', 'compile']

def load_constants():
    import re
    import os
    global ffi

    constants = ['AUDIT_ARCH_I386', 'AUDIT_ARCH_X86_64', 'AUDIT_ARCH_ARM']
    for match in chain(re.finditer(r"^\s*#\s*define\s+([^_][A-Z_]*)\s+([0-9bXx]+).*$",
                                   open("/usr/include/linux/filter.h", "r").read(),
                                   re.MULTILINE),
                       re.finditer(r"^\s*#\s*define\s+([^_][A-Z_]*)\s+([0-9bXx]+).*$",
                                   open("/usr/include/linux/seccomp.h", "r").read(),
                                   re.MULTILINE)):
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
struct sock_filter {
	...;
};
*/
struct sock_filter {	/* Filter block */
	uint16_t	code;	/* Actual filter code */
	uint8_t	jt;	/* Jump true */
	uint8_t	jf;	/* Jump false */
	uint32_t	k;		/* Generic multiuse field */
};


/*
struct sock_fprog {
	...;
};
*/
struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter *filter;
};


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
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/unistd.h>
""")
    for constant in constants:
        globals()[constant] = getattr(C, constant)
load_constants()

import sys, os
from collections import namedtuple
from struct import calcsize
BPFInstruction = namedtuple('BPFInstruction', ('opcode', 'jump_true', 'jump_false', 'k'))

def BPF_JUMP(code, k, jt, jf):
    return [BPFInstruction(code, jt, jf, k)]

def BPF_STMT(code, k):
    return BPF_JUMP(code, k, 0, 0)


JUMP_JT = object()
JUMP_JF = object()
LABEL_JT = object()
LABEL_JF = object()

ALLOW = BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
DENY_KILL = BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
def DENY_ERROR(errno):
    return BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO + errno)

def JUMP(label):
    return BPF_JUMP(BPF_JMP+BPF_JA, label,
                    JUMP_JT, JUMP_JF)
def LABEL(label):
    return BPF_JUMP(BPF_JMP+BPF_JA, label,
                    LABEL_JT, LABEL_JF)
def SYSCALL(nr, jt):
    if isinstance(nr, basestring):
        if not nr.startswith('__NR_'):
            nr = '__NR_'+nr
        nr = globals()[name]
    return BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 0, 1) + jt

if sys.byteorder == 'little':
    def LO_ARG(idx):
        return ffi.offsetof('struct seccomp_data', 'args[%d]' % idx)
elif sys.byteorder == 'big':
    # FIXME: assumes uint32_t is 4 bytes long
    def LO_ARG(idx):
        return ffi.offsetof('struct seccomp_data', 'args[%d]' % idx) + 4
else:
    raise RuntimeError("Unknown endianness")

# FIXME: assumes 8-bit bytes
if calcsize('l') == 4:
    HI_ARG = None
    def JEQ(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, value, 0, 1) + jt
    def JNE(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, value, 1, 0) + jt
    def JGT(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, value, 0, 1) + jt
    def JLT(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, value, 1, 0) + jt
    def JGE(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, value, 0, 1) + jt
    def JLE(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, value, 1, 0) + jt
    def JA(value, jt):
        return BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, value, 0, 1) + jt
    def ARG(i):
        return BPF_STMT(BPF_LD+BPF_W+BPF_ABS, LO_ARG(i))
elif calcsize('l') == 8:
    # FIXME: see above notes about length assumptions
    def hi32(x):
        return x & (1<<32)-1 << 32
    def lo32(x):
        return x & (1<<32)-1
    if sys.byteorder == 'little':
        def HI_ARG(idx):
            return ffi.offsetof('struct seccomp_data', 'args[%d]' % idx) + 4
    else:
        def HI_ARG(idx):
            return ffi.offsetof('struct seccomp_data', 'args[%d]' % idx)
    def JEQ(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, hi32(value), 0, 5) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, lo32(value), 0, 2) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def JNE(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, hi32(value), 5, 0) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, lo32(value), 2, 0) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def JGT(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, hi32(value), 4, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, hi32(value), 0, 5) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, lo32(value), 0, 2) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def JLT(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, hi32(value), 0, 4) \
               + BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, hi32(value), 0, 5) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, lo32(value), 2, 0) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def JGE(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, hi32(value), 4, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, hi32(value), 0, 5) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, lo32(value), 0, 2) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def JLE(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, hi32(value), 6, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, hi32(value), 0, 3) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, lo32(value), 2, 0) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def JA(value, jt):
        return   BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, hi32(value), 3, 0) \
               + BPF_STMT(BPF_LD+BPF_MEM, 0) \
               + BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, lo32(value), 0, 2) \
               + BPF_STMT(BPF_LD+BPF_MEM, 1) \
               + jt \
               + BPF_STMT(BPF_LD+BPF_MEM, 1)
    def ARG(i):
        return   BPF_STMT(BPF_LD+BPF_W+BPF_ABS, LO_ARG(idx)) \
               + BPF_STMT(BPF_ST, 0) \
               + BPF_STMT(BPF_LD+BPF_W+BPF_ABS, HI_ARG(idx)) \
               + BPF_STMT(BPF_ST, 1)
else:
    raise RuntimeError("Unusable long size", calcsize('l'))

LOAD_SYSCALL_NR = BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ffi.offsetof('struct seccomp_data', 'nr'))
LOAD_ARCH_NR = BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ffi.offsetof('struct seccomp_data', 'arch'))
arch = os.uname()[4]
if arch == 'i386':
    VALIDATE_ARCH =   LOAD_ARCH_NR \
                    + JEQ(AUDIT_ARCH_I386, DENY_KILL)
elif arch == 'x86_64':
    VALIDATE_ARCH =   LOAD_ARCH_NR \
                    + JEQ(AUDIT_ARCH_X86_64, DENY_KILL)
elif re.match(r'armv[0-9]+.*', arch):
    VALIDATE_ARCH =   LOAD_ARCH_NR \
                    + JEQ(AUDIT_ARCH_ARM, DENY_KILL)

def syscall_by_name(name):
    if not name.startswith('__NR_'):
        name = '__NR_'+name
    return globals()[name]


def compile(filter):
    label_dict = {}
    new_filter = [None] * len(filter)
    for i, (code, jump_true, jump_false, k) in reversed(enumerate(filter)):
        if jump_true is LABEL_JT and jump_false is LABEL_JF:
            # emit a noop, but record our offset
            jump_true = 0
            jump_false = 0
            k = 0
            label_dict[k] = i
        elif jump_true is JUMP_JT and jump_false is JUMP_JF:
            jump_true = 0
            jump_false = 0
            k = label_dict[k] - i - 1
        new_filter[i] = ffi.new('struct sock_filter', {'code'       : code,
                                                       'jump_true'  : jump_true,
                                                       'jump_false' : jump_false,
                                                       'k'          : k })
    return ffi.new('struct sock_fprog', {'len'    : len(new_filter),
                                         'filter' : new_filter})
