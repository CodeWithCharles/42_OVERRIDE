#!/usr/bin/env python3
leak = "0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d"
out = b""
for block in leak.split("0x"):
    if block:
        out += bytes.fromhex(block)[::-1]   # hex -> bytes, then undo little-endian
print(out.decode())
