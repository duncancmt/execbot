#!/bin/sh

dd if=/dev/zero of=/tmp/pi_swap.iso bs=1G count=6
qemu-system-arm \
    -m 256 \
    -kernel kernel-qemu \
    -machine versatilepb \
    -cpu arm1176 \
    -hda execbot.iso \
    -hdb /tmp/pi_swap.iso \
    -net nic \
    -net user \
    -append 'root=/dev/sda3 panic=1 rootfstype=ext4 rw'
rm /tmp/pi_swap.iso
    # -netdev user,id=pinet \
    # -device usb-net,netdev=pinet \
