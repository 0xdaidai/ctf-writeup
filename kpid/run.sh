#!/bin/sh

gcc -o exp -static exp.c -masm=intel -s -lpthread

mv ./exp ./rootfs
cd rootfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > ../rootfs.cpio.gz
cd ..

qemu-system-x86_64 \
    -kernel bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 512M \
    -smp 2 \
    -initrd rootfs.cpio.gz \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1 nokaslr" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -s
