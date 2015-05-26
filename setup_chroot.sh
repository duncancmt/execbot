#!/bin/bash

if [ -z "$1" ] ; then
    echo "Please supply a directory in which to make the chroot"
    exit 1
fi

PYPY_SANDBOX=$(which pypy-c-sandbox)
cp $PYPY_SANDBOX $1/$(dirname $PYPY_SANDBOX)
mkdir -p $1/usr/lib
cp $(ldd $PYPY_SANDBOX | awk '{print $3}' | grep '^/') $1/usr/lib
