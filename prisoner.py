import sandbox_filter
import prctl
import seccomp

# apply filter
prctl.prctl(prctl.PR_SET_SECCOMP,
            seccomp.SECCOMP_MODE_FILTER,
            sandbox_filter.filter)
# prevent changing filter
prctl.prctl(prctl.PR_SET_NO_NEW_PRIVS, 1)
