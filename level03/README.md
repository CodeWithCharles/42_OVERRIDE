# Level 03

## Base analysis

We start as usual :

```
level03@OverRide:~$ id
uid=2003(level03) gid=2003(level03) groups=2003(level03),100(users)
level03@OverRide:~$ ls -l
total 12
-rwsr-s---+ 1 level04 users 7307 Sep 10  2016 level03
level03@OverRide:~$ checksec --file ./level03
RELRO           STACK CANARY      NX            PIE       RPATH      RUNPATH      FILE
Partial RELRO   Canary found     NX enabled    No PIE    No RPATH   No RUNPATH   /home/users/level03/level03
```

The binary is setuid `level04`. NX is on and there's a stack canary, but this time we won't need any memory corruption : the program just asks for a password and validates it. Our job is to figure out the correct one through reverse engineering.

## Reverse engineering

### Overview of `main`

```c
__seed = time(0);
srand(__seed);
puts("***********************************");
puts("*\t\tlevel03\t\t**");
puts("***********************************");
printf("Password:");
__isoc99_scanf("%d", &local_14);     // reads our input as an integer
local_2c = 0x1337d00d;               // a constant is set up
test(local_14, 0x1337d00d);          // test(our_input, 0x1337d00d)
```

The `srand(time(...))` at the top looks like the password will depend on randomness — that's a deliberate red herring, as we'll see. Our input is read as an **integer** (`scanf("%d")`), and then `test()` is called with two arguments : our input and the constant `0x1337d00d`.

### `test()` is not actually random

The decompiled `test()` looks intimidating : a big `switch` whose cases all call `decrypt(...)`, plus a `default` branch that calls `rand()` first. But reading it carefully :

```c
pEVar1 = (EVP_PKEY_CTX *)(param_2 - param_1);   // 0x1337d00d - our_input
switch (pEVar1) {
  default:                       // only if (param_2 - param_1) > 0x15
    pEVar1 = (EVP_PKEY_CTX *)rand();
    decrypt(pEVar1, ...);
    break;
  case 0x1: decrypt(pEVar1, ...); break;
  case 0x2: decrypt(pEVar1, ...); break;
  ...
  case 0x15: decrypt(pEVar1, ...); break;
}
```

Every single case does the **exact same thing** : call `decrypt()` with `pEVar1` as the first argument. The value `pEVar1` is `0x1337d00d - our_input`. The `rand()` in the `default` branch only triggers when that difference is **greater than `0x15`** (the switch upper bound, from the `CMP ... 0x15 ; JA default` in the assembly).

So as long as we make `0x1337d00d - our_input` land in the range `0x1` to `0x15`, we control the value passed to `decrypt`, and `rand()` is never reached. The randomness is pure misdirection.

### `decrypt()` : a single-byte XOR check

```c
byte local_21[17];
local_21[0]  = 0x51; local_21[1]  = 0x7d; local_21[2]  = 0x7c; local_21[3]  = 0x75;
local_21[4]  = 0x60; local_21[5]  = 0x73; local_21[6]  = 0x66; local_21[7]  = 0x67;
local_21[8]  = 0x7e; local_21[9]  = 0x73; local_21[10] = 0x66; local_21[11] = 0x7b;
local_21[12] = 0x7d; local_21[13] = 0x7c; local_21[14] = 0x61; local_21[15] = 0x33;
local_21[16] = 0;

// XOR each byte with the low byte of ctx (= the value test passed in)
for (i = 0; i < 16; i++)
    local_21[i] = (byte)ctx ^ local_21[i];

if (memcmp(local_21, "Congratulations!", 17) == 0)
    system("/bin/sh");
else
    puts("\nInvalid Password");
```

The 16 encrypted bytes are each XORed with a single key byte — the low byte of `ctx`, which is exactly the `0x1337d00d - our_input` value computed in `test()`. If the result equals the string `"Congratulations!"`, we get a shell.

## Recovering the key

XOR is reversible, so the key byte is simply any encrypted byte XORed with its target plaintext byte. Taking the first one :

```
0x51 ('Q' encrypted) ^ 'C' (0x43) = 0x12
```

Checking the key `0x12` against the whole array :

```python
enc = [0x51,0x7d,0x7c,0x75,0x60,0x73,0x66,0x67,0x7e,0x73,0x66,0x7b,0x7d,0x7c,0x61,0x33]
print(bytes(b ^ 0x12 for b in enc))   # b'Congratulations!'
```

It decrypts cleanly to `Congratulations!`. So the key byte we need `decrypt` to use is `0x12`.

## Computing our input

We need `(0x1337d00d - our_input)` to equal `0x12`. Solving :

```
our_input = 0x1337d00d - 0x12 = 0x1337cffb = 322424827
```

This value also satisfies the switch constraint : `0x1337d00d - 322424827 = 0x12`, which is `<= 0x15`, so we land in `case 0x12` (a real case) and never hit the `rand()` default. The key `0x12` flows straight into `decrypt`, the XOR check passes, and `system("/bin/sh")` runs.

## Getting the shell

```bash
level03@OverRide:~$ ./level03
***********************************
*		level03		**
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Since the binary is setuid `level04`, the spawned shell runs with `level04`'s privileges, giving us the next level's password.

Level 03, clear... Progress to next level ? (Y/n) : ___
