#!/bin/bash

if [ -z "$1" ] ; then
    echo "Please supply a directory in which to make the chroot"
    exit 1
fi

mkdir -p $1/usr/lib
cp $(ldd $(which pypy-c-sandbox) | awk '{print $3}' | grep '^/') $1/usr/lib
