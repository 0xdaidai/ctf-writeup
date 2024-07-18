gcc -o exp -static exp.c -masm=intel -s -lpthread

mv ./exp ./rootfs
cd rootfs
find . -print0 \
| cpio --null -ov --format=newc > ../rootfs.cpio
cd ..

qemu-system-x86_64 \
    -m 512M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append 'console=ttyS0 nokaslr quiet loglevel=3 oops=panic panic=-1' \
    -netdev user,id=net \
    -device e1000,netdev=net \
    -no-reboot \
    -monitor /dev/null \
    -cpu qemu64,+smep,+smap \
    -smp cores=2,threads=1 \
    -nographic -s
