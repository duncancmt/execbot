#!/bin/bash

if [ -z "$1" ] ; then
    echo "Please supply a directory in which to make the chroot"
    exit 1
fi

cp $(ldd $(which pypy-c-sandbox) | awk '{print $3}' | grep '^/') $1
