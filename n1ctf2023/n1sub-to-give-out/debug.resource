target remote :1234
file ./sub.ko
bp 0xffffffffc0000000+0x314
commands
    set *(int *)(0xffffffffc0002344)=0x328
    set *(int *)0xffffffffc000235c=0x18
    c
end
bp 0xffffffffc0000000+0x183
c