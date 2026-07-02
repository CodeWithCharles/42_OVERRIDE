# 42 OVERRIDE

## Purpose ?

From the subject :

```
As a developer, you might have to work on software that will be used by hundreds of
people.
You have learned to develop more or less complex programs without taking security
into account.
With this project, you will quickly realize it’s rather easy to exploit issues that can
be very easily avoided.
Once you’re through with this project, you will have a clearer understanding of the
RAM. And this will really help you design a bugless program!
```

## Tool used

For this project, we have used :

- Kali as the OS
- SSH & SCP commands to bypass the need to log into the VM directly
- The override ISO provided by 42
- Ghidra to reverse engineer binaries (Almost impossible without that)
- WireMask to generate buffer overflows
- ASM, NASM, and objdump / hexdump to generate shellcode out of programs written in asm
- GDB (One of your best friends out there)
- Python to create small scripts to make the correction easier

## How is this repo orchestrated

For each levels we have :

- flag file
- the level executable
- sometimes the source code in C
- a readme to go through the steps
- a Ressources folder with every scripts and whatnot that were used for the exploit
