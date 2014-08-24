import re
import imp
import sys
from cffi import FFI


_constants = []
for match in re.finditer("^\s*#\s*define\s*PR_([A-Z_]+)\s.*$",
                         open("/usr/include/linux/prctl.h", "r").read(),
                         re.MULTILINE):
    _constants.append(match.group(1))

ffi = FFI()
_cdef_lines = """
    int prctl(int option, unsigned long arg2, unsigned long arg3,
              unsigned long arg4, unsigned long arg5);
"""
for _constant in _constants:
    _cdef_lines += """
    #define PR_%s ...
""" % _constant
ffi.cdef(_cdef_lines)

C = ffi.verify("""
#include <sys/prctl.h>
""", libraries=[])
prctl = C.prctl

for _constant in _constants:
    globals()[_constant] = getattr(C, "PR_"+_constant)
del _constant
del _constants




_capability_constants = []
for match in re.finditer("^\s*#\s*define\s*CAP_([A-Z_]+)\s.*$",
                         open("/usr/include/linux/capability.h", "r").read(),
                         re.MULTILINE):
    _capability_constants.append(match.group(1))

ffi = FFI()
_cdef_lines = ""
for _capability_constant in _capability_constants:
    _cdef_lines += """
    #define CAP_%s ...
""" % _capability_constant
ffi.cdef(_cdef_lines)

C = ffi.verify("""
#include <sys/capability.h>
""", libraries=[])

capability_constants = imp.new_module('capability_constants')

for _capability_constant in _capability_constants:
    capability_constants.__dict__[_capability_constant] = getattr(C, "CAP_"+_capability_constant)
del _capability_constant
del _capability_constants
sys.modules[__name__+'.capability_constants'] = capability_constants




_seccomp_constants = []
for match in re.finditer("^\s*#\s*define\s*SECCOMP_([A-Z_]+)\s.*$",
                         open("/usr/include/linux/seccomp.h", "r").read(),
                         re.MULTILINE):
    _seccomp_constants.append(match.group(1))

ffi = FFI()
_cdef_lines = ""
for _seccomp_constant in _seccomp_constants:
    _cdef_lines += """
    #define SECCOMP_%s ...
""" % _seccomp_constant
ffi.cdef(_cdef_lines)

C = ffi.verify("""
#include <linux/seccomp.h>
""", libraries=[])

seccomp_constants = imp.new_module('seccomp_constants')

for _seccomp_constant in _seccomp_constants:
    seccomp_constants.__dict__[_seccomp_constant] = getattr(C, "SECCOMP_"+_seccomp_constant)
del _seccomp_constant
del _seccomp_constants
sys.modules[__name__+'.seccomp_constants'] = seccomp_constants



del _cdef_lines
del ffi
del FFI
del C
del re
del imp
del sys
del match
