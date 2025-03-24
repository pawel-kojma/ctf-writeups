# Baby pwn

## Overview

We're given a source file `main.cpp`, a compiled binary `main_no_flag`, a dockerfile and some utf-8 strings library.

By looking at the source code we can see that binary first reads our input with `fgets` and calculates size of input using
`size` function from the utf-8 library. This size is used to check if we overflowed the buffer or not.

```cpp
[...]

    fgets(inp_buf,inp_buf_size,stdin);
    
    size_t user_inp_size = ww898::utf::size(inp_buf);
    if (user_inp_size > name_buf_size)
    {
        cout << "buffer overflow detected"<<endl;
        return 0;
    }

[...]
```

After that, out input is copied to much smaller buffer (64 vs 256 bytes). At the end the flag is printed if the `secret` variable contains
correct values "ping".

It is important to see how the buffers are laid out in memory. We can use gdb for that.

```
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004011c6 <+0>:	push   rbp
   0x00000000004011c7 <+1>:	mov    rbp,rsp
   0x00000000004011ca <+4>:	sub    rsp,0x160
   0x00000000004011d1 <+11>:	mov    DWORD PTR [rbp-0x15],0x34333231 // secret "1234\x00"
   0x00000000004011d8 <+18>:	mov    BYTE PTR [rbp-0x11],0x0
   0x00000000004011dc <+22>:	mov    QWORD PTR [rbp-0x60],0x0
   0x00000000004011e4 <+30>:	mov    QWORD PTR [rbp-0x58],0x0
   ...
   0x00000000004013ad <+487>:	lea    rax,[rbp-0x160] // inp_buf
   0x00000000004013b4 <+494>:	mov    esi,0x100
   0x00000000004013b9 <+499>:	mov    rdi,rax
   0x00000000004013bc <+502>:	call   0x4010a0 <fgets@plt>
   ...
   0x000000000040140a <+580>:	mov    eax,DWORD PTR [rbp-0x8]
   0x000000000040140d <+583>:	cdqe
   0x000000000040140f <+585>:	movzx  edx,BYTE PTR [rbp+rax*1-0x160] // read ith byte from inp_buf
   0x0000000000401417 <+593>:	mov    eax,DWORD PTR [rbp-0x8]
   0x000000000040141a <+596>:	cdqe
   0x000000000040141c <+598>:	mov    BYTE PTR [rbp+rax*1-0x60],dl // write byte to name_buf
   0x0000000000401420 <+602>:	add    DWORD PTR [rbp-0x8],0x1
   0x0000000000401424 <+606>:	mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000401427 <+609>:	cdqe
   0x0000000000401429 <+611>:	movzx  eax,BYTE PTR [rbp+rax*1-0x160]
   0x0000000000401431 <+619>:	cmp    al,0xa
   0x0000000000401433 <+621>:	jne    0x40140a <main+580>
```

So we have:
- 256 bytes of inp_buf at `rbp-0x160`
- 64 bytes of name_buf at `rbp-0x60`, just after inp_buf
- 5 bytes of secret at `rbp-0x15`, 75 bytes after name_buf start

## Solve

The plan is to find a byte sequence that terminates `ww98::utf::size`, but does not terminate `fgets`.
This way we can overflow as much as we want without triggering overflow check.
The payload will be: `utf8_term_seq + b'a'*(75 - len(utf8_term_seq)) + b'ping\n'`
We start with termination sequence, then 75 bytes to fill name_buf and get to secret variable (remember that inp_buf is copied to name_buf).

`brute.py` script bruteforces the termination sequence. For me it was `\x01\x00`.
`solve.py` just enters the payload above.
