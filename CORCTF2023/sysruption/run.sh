#!/bin/sh
make

mv ./exp ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > ../initramfs.cpio.gz
cd ..

qemu-system-x86_64 \
    -m 4096M \
    -smp 1 \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 loglevel=3 panic=-1 pti=off nokaslr" \
    -no-reboot \
    -monitor /dev/null \
    -cpu host \
    -netdev user,id=net \
    -device e1000,netdev=net \
    -initrd "./initramfs.cpio.gz" \
    -enable-kvm \
    -s

