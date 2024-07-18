#!/bin/sh

gcc exp.c -o ./rootfs/exp -static
cd rootfs
find . -print0 \
| cpio --null -ov --format=newc > ../rootfs.cpio
cd ..

qemu-system-x86_64 \
    -m 512M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -monitor /dev/null \
    -append "root=/dev/ram console=ttyS0 quiet nokaslr kpti=1 panic=1" \
    -cpu kvm64,+smep,+smap \
    -nographic \
    -no-reboot \
    -s
