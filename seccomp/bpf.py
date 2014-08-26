from itertools import chain

def load_constants():
    import re

    constants = ['AUDIT_ARCH_I386', 'AUDIT_ARCH_X86_64', 'AUDIT_ARCH_ARM']
    for match in chain(re.finditer(r"^\s*#\s*define\s+[^_]([A-Z_]*)\s+(\S+).*$",
                                   open("/usr/include/linux/filter.h", "r".read()),
                                   re.MULTILINE),
                       re.finditer(r"^\s*#\s*define\s+[^_]([A-Z_]*)\s+(\S+).*$",
                                   open("/usr/include/linux/seccomp.h", "r".read()),
                                   re.MULTILINE),
                       re.finditer(r"^\s*#\s*define\s+(__NR[A-Z_]+).*$",
                                   open("/usr/include/seccomp.h", "r".read()),
                                   re.MULTILINE)):
        try:
            int(match.group(2), base=0)
        except ValueError:
            pass
        else:
            constants.append(match.group(1))

    from cffi import FFI
    ffi = FFI()

    cdef_lines = """
/*
struct sock_filter {
    ...;
};
*/
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
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
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
"""
    for constant in constants:
        cdef_lines += "#define %s ...\n" % constant
    ffi.cdef(cdef_lines)
    C = ffi.verify("""
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
""")
    for constant in constants:
        globals()[constant] = getattr(C, constant)
    globals()['ffi'] = ffi
    globals()['struct_sock_filter'] = C.sock_filter
    globals()['struct_sock_fprog'] = C.sock_fprog
    globals()['struct_seccomp_data'] = C.seccomp_data
load_constants()

import sys, os
from collections import namedtuple
BPFInstruction = namedtuple('BPFInstruction', ('opcode', 'jump_true', 'jump_false', 'k'))

def BPF_JUMP(code, k, jt, jf):
    return BPFInstruction(code, jt, jf, k)

def BPF_STMT(code, k):
    BPF_JUMP(code, k, 0, 0)


JUMP_JT = object()
JUMP_JF = object()
LABEL_JT = object()
LABEL_JF = object()

ALLOW = BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
DENY = BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

def JUMP(label):
    return BPF_JUMP(BPF_JMP+BPF_JA, label,
                    JUMP_JT, JUMP_JF)
def LABEL(label):
    return BPF_JUMP(BPF_JMP+BPF_JA, label,
                    LABEL_JT, LABEL_JF)
def SYSCALL(nr, jt):
    return BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 0, 1) + jt

if sys.byteorder == 'little':
    def LO_ARG(idx):
        return ffi.offsetof(struct_seccomp_data, 'args[%d]' % idx)
elif sys.byteorder == 'big':
    # FIXME: assumes __u32 is 4 bytes long
    def LO_ARG(idx):
        return ffi.offsetof(struct_seccomp_data, 'args[%d]') + 4
else:
    raise RuntimeError("Unknown endianness")

# FIXME: assumes 8-bit bytes
if calcsize('l') == 4:
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
    def HI_ARG(idx):
        return ffi.offsetof(struct_seccomp_data, 'args[%d]' % idx) + 4
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

LOAD_SYSCALL_NR = BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ffi.offsetof(struct_seccomp_data, 'nr'))
LOAD_ARCH_NR = BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ffi.offsetof(struct_seccomp_data, 'arch'))
arch = os.uname()[4]
if arch == 'i386':
    VALIDATE_ARCH =   LOAD_ARCH_NR \
                    + JEQ(AUDIT_ARCH_I386, 1) \
                    + DENY
elif arch == 'x86_64':
    VALIDATE_ARCH =   LOAD_ARCH_NR \
                    + JEQ(AUDIT_ARCH_X86_64, 1) \
                    + DENY
elif re.match(r'armv[0-9]+.*', arch):
    VALIDATE_ARCH =   LOAD_ARCH_NR \
                    + JEQ(AUDIT_ARCH_ARM, 1) \
                    + DENY

def syscall_by_name(name):
    if not name.startswith('__NR_'):
        name = '__NR_'+name
    return globals()[name]

def resolve_jumps(filter):
    label_dict = {}
    new_filter = [None] * len(filter)
    for i, (code, jump_true, jump_false, k) in reversed(enumerate(filter)):
        if jump_true is LABEL_JT and jump_false is LABEL_JF:
            jump_true = 0
            jump_false = 0
            label_dict[k] = i
            k = 0
        elif jump_true is JUMP_JT and jump_false is JUMP_JF:
            jump_true = 0
            jump_false = 0
            k = label_dict[k] - i + 1
        # FIXME: assumes 8-bit bytes
        if sys.byteorder == 'little':
            new_filter[i] = ffi.new(struct_sock_filter, {'code'       : code,
                                                         'jump_true'  : jump_true,
                                                         'jump_false' : jump_false,
                                                         'k'          : k })
    return ffi.new(struct_sock_fprog, {'len'    : len(new_filter),
                                       'filter' : new_filter})
