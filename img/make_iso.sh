#!/bin/sh
set -x
set -e

dd if=/dev/zero of=execbot.iso bs=496762880 count=16
fdisk execbot.iso <<EOF
o
n
p
1

+100M
t
c
n
p
2

+1G
t
2
82
n
p
3


w

EOF
LOOP_DEV=$(losetup -f)
echo loop device is $LOOP_DEV
sudo losetup -P -f execbot.iso
sudo mkfs.vfat "${LOOP_DEV}"p1
sudo mkswap "${LOOP_DEV}"p2
sudo mkfs.ext4 "${LOOP_DEV}"p3
mkdir execbot_mountpoint
sudo mount "${LOOP_DEV}"p3 execbot_mountpoint
sudo mkdir execbot_mountpoint/boot
sudo mount "${LOOP_DEV}"p1 execbot_mountpoint/boot
sudo tar -zxf ArchLinuxARM-rpi-latest.tar.gz -C execbot_mountpoint/
sudo umount -R execbot_mountpoint
rmdir execbot_mountpoint
sudo losetup -D "${LOOP_DEV}"
sudo sync

