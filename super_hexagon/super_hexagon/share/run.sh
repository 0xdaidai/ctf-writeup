#!/bin/bash

./qemu-system-aarch64 -S -s -nographic -machine hitcon -cpu hitcon -bios \
    ./bios.bin -monitor /dev/null 2>/dev/null -serial null
