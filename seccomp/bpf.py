__all__ = []

def load_constants():
    import re
    global ffi
    global C
    constants = []
    for match in re.finditer(r"^\s*#\s*define\s+([^_][A-Z_]*)\s+([0-9bXx]+).*$",
                             open("/usr/include/linux/filter.h", "r").read(),
                             re.MULTILINE):
        try:
            int(match.group(2), base=0)
        except ValueError:
            pass
        else:
            constant = match.group(1)
            __all__.append(constant)
            constants.append(constant)

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

void *malloc(size_t size);
void free(void *ptr);
"""
    for constant in constants:
        cdef_lines += "#define %s ...\n" % constant
    ffi.cdef(cdef_lines)
    C = ffi.verify("""
#include <linux/filter.h>
#include <stdlib.h>
""")
    for constant in constants:
        globals()[constant] = getattr(C, constant)
load_constants()


from collections import namedtuple
from struct import calcsize
BPFInstruction = namedtuple('BPFInstruction', ('opcode', 'jump_true', 'jump_false', 'k'))


__all__ += ['JUMP', 'LABEL', 'STMT', 'RET', 'RET_IMM']
def JUMP(code, k, jt=0, jf=0):
    return [BPFInstruction(BPF_JMP+code, jt, jf, k)]

def LABEL(label):
    return JUMP(BPF_JA, label, 0, 0)

def STMT(code, k):
    return [BPFInstruction(code, 0, 0, k)]

RET = STMT(BPF_RET+BPF_A, 0)
def RET_IMM(value):
    return STMT(BPF_RET+BPF_K, value)

# Arithmetic instructions with an immediate value as the right argument
__all__ += ['ADD_IMM', 'SUB_IMM', 'MUL_IMM', 'DIV_IMM', 'AND_IMM', 'OR_IMM',
            'LSH_IMM', 'RSH_IMM']
def ADD_IMM(value):
    return STMT(BPF_ALU+BPF_ADD+BPF_K, value)
def SUB_IMM(value):
    return STMT(BPF_ALU+BPF_SUB+BPF_K, value)
def MUL_IMM(value):
    return STMT(BPF_ALU+BPF_MUL+BPF_K, value)
def DIV_IMM(value):
    return STMT(BPF_ALU+BPF_DIV+BPF_K, value)
def AND_IMM(value):
    return STMT(BPF_ALU+BPF_AND+BPF_K, value)
def OR_IMM(value):
    return STMT(BPF_ALU+BPF_OR+BPF_K, value)
def LSH_IMM(value):
    return STMT(BPF_ALU+BPF_LSH+BPF_K, value)
def RSH_IMM(value):
    return STMT(BPF_ALU+BPF_RSH+BPF_K, value)

# Arithmetic instructions with the index register as the right argument
__all__ += ['ADD', 'SUB', 'MUL', 'DIV', 'AND', 'OR', 'LSH', 'RSH', 'NEG']
ADD = STMT(BPF_ALU+BPF_ADD+BPF_X, 0)
SUB = STMT(BPF_ALU+BPF_SUB+BPF_X, 0)
MUL = STMT(BPF_ALU+BPF_MUL+BPF_X, 0)
DIV = STMT(BPF_ALU+BPF_DIV+BPF_X, 0)
AND = STMT(BPF_ALU+BPF_AND+BPF_X, 0)
OR  = STMT(BPF_ALU+BPF_OR+BPF_X, 0)
LSH = STMT(BPF_ALU+BPF_LSH+BPF_X, 0)
RSH = STMT(BPF_ALU+BPF_RSH+BPF_X, 0)
NEG = STMT(BPF_ALU+BPF_NEG, 0)

# Load from immediate address
__all__ += ['LDW_IMM', 'LDH_IMM', 'LDB_IMM']
def LDW_IMM(value):
    return STMT(BPF_LD+BPF_W+BPF_ABS, value)
def LDH_IMM(value):
    return STMT(BPF_LD+BPF_H+BPF_ABS, value)
def LDB_IMM(value):
    return STMT(BPF_LD+BPF_B+BPF_ABS, value)

# Load from address relative to index register
__all__ += ['LDW', 'LDH', 'LDB']
def LDW(value=0):
    return STMT(BPF_LD+BPF_W+BPF_IND, value)
def LDH(value=0):
    return STMT(BPF_LD+BPF_H+BPF_IND, value)
def LDB(value=0):
    return STMT(BPF_LD+BPF_B+BPF_IND, value)

# Other load-like instructions
__all__ += ['LEN', 'CONST', 'MEM']
LEN = STMT(BPF_LD+BPF_W+BPF_LEN, 0)
def CONST(value):
    return STMT(BPF_LD+BPF_IMM, value)
def MEM(value):
    return STMT(BPF_LD+BPF_MEM, value)

# Instructions that load into the index register
__all__ += ['CONSTX', 'MEMX', 'LENX', 'MSH']
def CONSTX(value):
    return STMT(BPF_LDX+BPF_W+BPF_IMM, value)
def MEMX(value):
    return STMT(BPF_LDX+BPF_W+BPF_MEM, value)
LENX = STMT(BPF_LDX+BPF_W+BPF_LEN, 0)
def MSH(value):
    return STMT(BPF_LDX+BPF_B+BPF_MSH, value)

# Store instructions
__all__ += ['ST', 'STX']
def ST(value):
    return STMT(BPF_ST, value)
def STX(value):
    return STMT(BPF_STX, value)

# Misc instructions
__all__ += ['TAX', 'TXA']
TAX = STMT(BPF_MISC+BPF_TAX, 0)
TXA = STMT(BPF_MISC+BPF_TXA, 0)

# Jump instructions
__all__ += ['JEQ_IMM', 'JNE_IMM', 'JGT_IMM', 'JLT_IMM',
            'JGE_IMM', 'JLE_IMM', 'JSET_IMM']
def JEQ_IMM(value, jt):
    return JUMP(BPF_JEQ+BPF_K, value, 0, len(jt)) + jt
def JNE_IMM(value, jt):
    return JUMP(BPF_JEQ+BPF_K, value, len(jt), 0) + jt
def JGT_IMM(value, jt):
    return JUMP(BPF_JGT+BPF_K, value, 0, len(jt)) + jt
def JLT_IMM(value, jt):
    return JUMP(BPF_JGE+BPF_K, value, len(jt), 0) + jt
def JGE_IMM(value, jt):
    return JUMP(BPF_JGE+BPF_K, value, 0, len(jt)) + jt
def JLE_IMM(value, jt):
    return JUMP(BPF_JGT+BPF_K, value, len(jt), 0) + jt
def JSET_IMM(value, jt):
    return JUMP(BPF_JSET+BPF_K, value, 0, len(jt)) + jt

__all__ += ['JEQ', 'JNE', 'JGT', 'JLT', 'JGE', 'JLE', 'JSET']
def JEQ(jt):
    return JUMP(BPF_JEQ+BPF_X, 0, 0, len(jt)) + jt
def JNE(jt):
    return JUMP(BPF_JEQ+BPF_X, 0, len(jt), 0) + jt
def JGT(jt):
    return JUMP(BPF_JGT+BPF_X, 0, 0, len(jt)) + jt
def JLT(jt):
    return JUMP(BPF_JGE+BPF_X, 0, len(jt), 0) + jt
def JGE(jt):
    return JUMP(BPF_JGE+BPF_X, 0, 0, len(jt)) + jt
def JLE(jt):
    return JUMP(BPF_JGT+BPF_X, 0, len(jt), 0) + jt
def JSET(jt):
    return JUMP(BPF_JSET+BPF_X, 0, 0, len(jt)) + jt

# on 64-bit systems, it is useful to be able to compare 64-bit values with BPF
# these programs expect the upper 32-bits of the value to be compared in the
# accumulator and the lower and upper 32-bits of the values to be compared in
# M[0] and M[1], respectively.
if calcsize('l') >= 8:
    def hi32(x):
        return x & (1<<32)-1 << 32
    def lo32(x):
        return x & (1<<32)-1
    __all__ += ['BIG_JEQ_IMM', 'BIG_JNE_IMM', 'BIG_JGT_IMM', 'BIG_JLT_IMM',
                'BIG_JGE_IMM', 'BIG_JLE_IMM', 'BIG_JSET_IMM']
    def BIG_JEQ_IMM(value, jt):
        return   JUMP(BPF_JEQ+BPF_K, hi32(value), 0, 4+len(jt)) \
               + MEM(0) \
               + JUMP(BPF_JEQ+BPF_K, lo32(value), 0, 1+len(jt)) \
               + MEM(1) \
               + jt \
               + MEM(1)
    def BIG_JNE_IMM(value, jt):
        return   JUMP(BPF_JEQ+BPF_K, hi32(value), 4+len(jt), 0) \
               + MEM(0) \
               + JUMP(BPF_JEQ+BPF_K, lo32(value), 1+len(jt), 0) \
               + MEM(1) \
               + jt \
               + MEM(1)
    def BIG_JGT_IMM(value, jt):
        return   JUMP(BPF_JGT+BPF_K, hi32(value), 4, 0) \
               + JUMP(BPF_JEQ+BPF_K, hi32(value), 0, 4+len(jt)) \
               + MEM(0) \
               + JUMP(BPF_JGT+BPF_K, lo32(value), 0, 1+len(jt)) \
               + MEM(1) \
               + jt \
               + MEM(1)
    def BIG_JLT_IMM(value, jt):
        return   JUMP(BPF_JGE+BPF_K, hi32(value), 0, 4) \
               + JUMP(BPF_JEQ+BPF_K, hi32(value), 0, 4+len(jt)) \
               + MEM(0) \
               + JUMP(BPF_JGT+BPF_K, lo32(value), 1+len(jt), 0) \
               + MEM(1) \
               + jt \
               + MEM(1)
    def BIG_JGE_IMM(value, jt):
        return   JUMP(BPF_JGT+BPF_K, hi32(value), 4, 0) \
               + JUMP(BPF_JEQ+BPF_K, hi32(value), 0, 4+len(jt)) \
               + MEM(0) \
               + JUMP(BPF_JGE+BPF_K, lo32(value), 0, 1+len(jt)) \
               + MEM(1) \
               + jt \
               + MEM(1)
    def BIG_JLE_IMM(value, jt):
        return   JUMP(BPF_JGT+BPF_K, hi32(value), 5+len(jt), 0) \
               + JUMP(BPF_JEQ+BPF_K, hi32(value), 0, 3) \
               + MEM(0) \
               + JUMP(BPF_JGT+BPF_K, lo32(value), 1+len(jt), 0) \
               + MEM(1) \
               + jt \
               + MEM(1)
    def BIG_JSET_IMM(value, jt):
        return   JUMP(BPF_JSET+BPF_K, hi32(value), 3, 0) \
               + MEM(0) \
               + JUMP(BPF_JSET+BPF_K, lo32(value), 0, 1+len(jt)) \
               + MEM(1) \
               + jt \
               + MEM(1)

__all__ += ['compile']
def compile(filter):
    label_dict = {}
    c_filter_mem = C.malloc(ffi.sizeof('struct sock_filter')*len(filter))
    c_filter = ffi.cast('struct sock_filter[%d]' % len(filter), c_filter_mem)
    for i, (code, jump_true, jump_false, k) in reversed(tuple(enumerate(filter))):
        if isinstance(k, basestring): # label
            # emit a noop, but record our offset
            label_dict[k] = i
            k = 0
        if isinstance(jump_true, basestring): # labeled target
            jump_true = label_dict[jump_true] - i - 1
        if isinstance(jump_false, basestring): # labeled target
            jump_false = label_dict[jump_false] - i - 1
        instr = c_filter[i]
        instr.code = code
        instr.jt = jump_true
        instr.jf = jump_false
        instr.k = k

    retval_mem = C.malloc(ffi.sizeof('struct sock_fprog'))
    retval = ffi.cast('struct sock_fprog *', retval_mem)

    def destructor(retval):
        C.free(retval_mem)
        C.free(c_filter_mem)
    retval = ffi.gc(retval, destructor)
    retval.len = len(c_filter)
    retval.filter = c_filter
    return retval
