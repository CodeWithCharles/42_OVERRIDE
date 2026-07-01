# Level 06

## Base analysis

```
level06@OverRide:~$ id
uid=1006(level06) gid=1006(level06) groups=1006(level06),100(users)
level06@OverRide:~$ ls -l
total 12
-rwsr-s---+ 1 level07 users 6944 Sep 10  2016 level06
level06@OverRide:~$ checksec --file ./level06
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level06/level06
```

Setuid `level07`, with canary and NX both on. No memory-corruption angle this time — the program asks for a login and a serial, and only spawns a shell if the serial matches. It's a **keygen** challenge : we reverse the algorithm that turns a login into its expected serial.

Running it shows the flow :

```
./level06
-> Enter Login: tooeasy
-> Enter Serial: 0
```

## Reverse engineering

`main` reads a login with `fgets` (32 bytes) and a serial with `scanf("%d")`, then calls `auth(login, serial)`. If `auth` returns 0, we get `system("/bin/sh")`.

The interesting logic is all in `auth`. Cleaned up :

```c
int auth(char *login, unsigned serial)
{
    login[strcspn(login, "\n")] = '\0';       // strip newline
    int len = strnlen(login, 0x20);

    if (len < 6)                               // login must be >= 6 chars
        return 1;

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) // anti-debug
        return 1;                              // "TAMPERING DETECTED"

    // seed from the 4th character (index 3)
    unsigned acc = (login[3] ^ 0x1337) + 0x5eeded;

    for (int i = 0; i < len; i++) {
        if (login[i] < 0x20)                   // reject control bytes
            return 1;
        acc += (login[i] ^ acc) % 0x539;       // 0x539 = 1337
    }

    return (serial == acc) ? 0 : 1;            // match -> success
}
```

So the serial is a pure function of the login :

1. Seed : `acc = (login[3] ^ 0x1337) + 0x5eeded`.
2. For each character, `acc += (login[i] ^ acc) % 1337`.
3. The serial must equal the final `acc`.

A couple of assembly-level details worth noting :

- The characters are sign-extended (`movsbl`), so bytes ≥ 0x80 would be treated as negative. For a normal ASCII login this doesn't matter.
- In the disassembly the `% 0x539` shows up as a `mul` by the magic constant `0x88233b2b` followed by shifts (`shr`, `add`, `shr 0xa`, `imul 0x539`, `sub`). That's just GCC's standard optimization for dividing by the constant 1337 — it computes the remainder without a real `div`.

## The anti-debug (`ptrace`)

`auth` calls `ptrace(PTRACE_TRACEME)`. If the process is already being traced (e.g. under gdb), this returns `-1`, and the program bails with "TAMPERING DETECTED". Under gdb we simply skip past the check :

```
(gdb) b *0x080487b5          # the ptrace call
(gdb) b *0x08048866          # the final cmp (serial vs computed value)
(gdb) run
-> Enter Login: tooeasy
-> Enter Serial: 0
Breakpoint 1, 0x080487b5 in auth ()
(gdb) jump *0x080487ed        # jump over the ptrace result check
Breakpoint 2, 0x08048866 in auth ()
(gdb) p *(int*)($ebp-0x10)    # the computed serial (local_14)
$1 = 6233784
```

At the final comparison, the expected serial for `tooeasy` is sitting in `local_14` (at `$ebp-0x10`) : **6233784**. That confirms the algorithm.

## Keygen

Rather than lean on gdb every time, we reimplement the algorithm (see `keygen06.py`) and compute the serial for any login :

```bash
python2 keygen06.py tooeasy
6233784
```

## Getting the shell

Feed the login and its computed serial to the real binary (outside gdb, so `ptrace` succeeds) :

```
./level06
-> Enter Login: tooeasy
-> Enter Serial: 6233784
Authenticated!
$ cat /home/users/level07/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Since the binary is setuid `level07`, the shell runs as `level07` and we can read the next password.

Level 06, clear... Progress to next level ? (Y/n) : ___
