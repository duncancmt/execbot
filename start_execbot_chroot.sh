#!/bin/bash
set -x
set -e
LOOP_DEV=$(losetup -f)
echo loop device is $LOOP_DEV
sudo losetup -P -f execbot.iso

mkdir execbot_mountpoint
sudo mount "${LOOP_DEV}"p3 execbot_mountpoint
sudo mount "${LOOP_DEV}"p1 execbot_mountpoint/boot
sudo mount --bind /dev execbot_mountpoint/dev
sudo mount --bind /proc execbot_mountpoint/proc
sudo mount --bind /sys execbot_mountpoint/sys

echo ':arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:' | sudo tee /proc/sys/fs/binfmt_misc/register || true

cd execbot_mountpoint
sudo cp /usr/bin/qemu-arm-static usr/bin/

( sudo chroot . ; exit 0 )

sudo rm usr/bin/qemu-arm-static
cd ..
sudo umount -R execbot_mountpoint
rmdir execbot_mountpoint
sudo losetup -d $LOOP_DEV
