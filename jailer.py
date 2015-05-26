import urllib2

from rpython.translator.sandbox.vfs import Dir, File

from sandbox.jail import JailedProc

MAX_HEAP = 16777216
TMP_DIR = '/execbot/tmp'
CHROOT_DIR = '/execbot/chroot'
JAIL_SIZE = 16
JAIL_UID = 99
JAIL_GID = 99

prisoners = {}
procdir = Dir({})


def clean_jail():
    to_delete = set()
    for i, prisoner in prisoners.iteritems():
        if prisoner.poll() is not None:
            to_delete.add(i)
    for i in to_delete:
        del prisoners[i]
        del procdir.entries[str(i)]


def jailed_script(url):
    try:
        response = urllib2.urlopen(url)
        content = response.read()
    except:
        raise ValueError("Could not download script")

    jailed_expression(content)

def jailed_expression(expr):
    clean_jail()

    if len(prisoners) >= JAIL_SIZE:
        raise ValueError("Jail is full")


    args = ['-c', expr]
    exe = '/usr/bin/pypy-c-sandbox'
    for i in xrange(JAIL_SIZE):
        if i not in prisoners:
            pid = i
    new = JailedProc(args, exe, JAIL_UID, JAIL_GID,
                     tmppath=TMP_DIR, chroot=CHROOT_DIR,
                     procdir=procdir, p_table=prisoners)
    prisoners[pid] = new
    procdir.entries[str(pid)] = Dir({"source":File(expr)})

    clean_jail()
    


def feed_prisoners(food):
    clean_jail()
    for prisoner in prisoners.itervalues():
        prisoner.put(food)
    poop = {}
    for i, prisoner in prisoners.iteritems():
        poop[i] = prisoner.get()
    clean_jail()
    return poop
