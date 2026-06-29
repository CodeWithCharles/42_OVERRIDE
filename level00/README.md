# Level 00

## Base analysis

First of all, we need to know who we are, and which files belong to us.
For that, we run the command `id` :

```
level00@OverRide:~$ id
uid=1000(level00) gid=1000(level00) groups=1000(level00),100(users)
```

Then, let's see what's lying around in our home directory :

```
level00@OverRide:~$ ls -l
total 8
-rwsr-sr-x 1 level00 level00 5138 Mar  6  2016 level00
```

Interesting... The file `level00` belongs to us, but look at those permissions. The `s` bits (setuid and setgid) mean that when we execute it, it runs with the privileges of its owner rather than ours. That's exactly the kind of thing we're looking for.

## Running the binary

Let's launch it and see what happens :

```
level00@OverRide:~$ ./level00
***********************************
* 	     -Level00 -		  *
***********************************
Password:
```

It asks for a password. Without knowing it, we're stuck, so let's dig into the binary itself.

## Reverse engineering with Ghidra

We load the binary into [Ghidra](https://ghidra-sre.org/) and let it decompile the `main` function back into something resembling C :

```c
bool main(void)
{
  int local_14 [4];

  puts("***********************************");
  puts("* \t     -Level00 -\t\t  *");
  puts("***********************************");
  printf("Password:");
  __isoc99_scanf(&DAT_08048636,local_14);
  if (local_14[0] != 0x149c) {
    puts("\nInvalid Password!");
  }
  else {
    puts("\nAuthenticated!");
    system("/bin/sh");
  }
  return local_14[0] != 0x149c;
}
```

Reading the code is straightforward. Our input is read with `scanf` into `local_14`, then compared against the hexadecimal value `0x149c`. If it matches, the program prints "Authenticated!" and spawns a shell with `system("/bin/sh")`. If not, we get "Invalid Password!".

## Cracking the password

So the password is simply `0x149c`, but expressed in hexadecimal. We need to convert it to decimal, since that's what the program reads from us :

```
level00@OverRide:~$ python3 -c 'print(0x149c)'
5276
```

The password is `5276`. Let's feed it to the program :

```
level00@OverRide:~$ ./level00
***********************************
* 	     -Level00 -		  *
***********************************
Password:5276

Authenticated!
$
```

And we get our shell. Since the binary runs with elevated privileges, this shell does too. We can now read the next level's password :

```
$ whoami
level01
$ cat /home/user/level01/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Level 00, clear... Progress to next level ? (Y/n) : ___
