import re
import imp
import sys
import os
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


def prctl(option, arg2, arg3, arg4, arg5):
    option = ffi.cast('int', option)
    arg2 = ffi.cast('unsigned long', arg2)
    arg3 = ffi.cast('unsigned long', arg3)
    arg4 = ffi.cast('unsigned long', arg4)
    arg5 = ffi.cast('unsigned long', arg5)
    ret = C.prctl(option, arg2, arg3, arg4, arg5)
    if ret != 0:
        raise OSError(ffi.errno, os.strerror(ffi.errno))

for _constant in _constants:
    globals()[_constant] = getattr(C, _constant)
