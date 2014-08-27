import re
import imp
import sys
from cffi import FFI

__all__ = ['prctl']
_constants = []
for match in re.finditer(r"^\s*#\s*define\s*(PR_[A-Z_]+)\s.*$",
                         open("/usr/include/linux/prctl.h", "r").read(),
                         re.MULTILINE):
    _constant = match.group(1)
    __all__.append(_constant)
    _constants.append(_constant)



ffi = FFI()
_cdef_lines = """
    int prctl(int option, unsigned long arg2, unsigned long arg3,
              unsigned long arg4, unsigned long arg5);
"""
for _constant in _constants:
    _cdef_lines += """
    #define %s ...
""" % _constant
ffi.cdef(_cdef_lines)

C = ffi.verify("""
#include <sys/prctl.h>
""", libraries=[])



prctl = C.prctl

for _constant in _constants:
    globals()[_constant] = getattr(C, _constant)
