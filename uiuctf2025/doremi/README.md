# Do re mi

This was a heap challange with `musl` libc and `mimalloc` as an allocator.

We're given a challange binary and source code.

Program gives standard CRUD interface:
```
###################################
# Yet Another Heap Note Challenge #
###################################
    What Would You Like to Do:
        1. Create a Note
        2. Delete a Note
        3. Read a Note
        4. Update a Note
        5. Exit
YAHNC>
```

Mimalloc is a fast allocator with MT support and can be compiled in "secure mode".
This means it will have stuff like canaries, guard pages, random heap layout and
delayed allocation of free blocks. In this challange we have the standard version.

I started by examining how the heap looks like in memory and what is available.
Mimalloc creates a separate memory mapping where the heap is stored.
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
     0x20000000000      0x20040000000 rw-p 40000000      0 [anon_20000000] <-------- The heap
    0x555555554000     0x555555555000 r--p     1000      0 chal
    0x555555555000     0x555555556000 r-xp     1000   1000 chal
    0x555555556000     0x555555557000 r--p     1000   2000 chal
[...]
```

The program stores all allocated blocks in global `notes` variable.
The size of each allocation is 128 bytes.
Below I allocated 1 block.
```
pwndbg> p (char *[16])notes
$2 = {0x276ae010080 "", 0x0 <repeats 15 times>}
```

Lets see memory content of the first block.
```
pwndbg> x/4gx 0x276ae010080
0x276ae010080:  0x00000276ae010100      0x0000000000000000
0x276ae010090:  0x0000000000000000      0x0000000000000000
```

Right away we have a heap leak by reading contents of `notes[0]`.
The pointer we see tells mimalloc where he should allocate next block of size 128.

Mimalloc has an initial singly-linked list of 33 blocks of size 128 bytes.
It will drain this list before reaching into another one where freed blocks are stored.
Telescope command will display this list of blocks parially.
```
pwndbg> telescope 0x276ae010080 1
00:0000│  0x276ae010080 —▸ 0x276ae010100 —▸ 0x276ae010180 —▸ 0x276ae010200 —▸ 0x276ae010280 ◂— ...
```

What really helped me during solving it was compiling mimalloc with debug symbols and
debugging with source code.
Below we can see snippet of code that allocates blocks by popping them from the linked list.
```c
extern inline void* _mi_page_malloc_zero(mi_heap_t* heap, mi_page_t* page, size_t size, bool zero) mi_attr_noexcept
{
 [...]
  // check the free list
  mi_block_t* const block = page->free;
  if mi_unlikely(block == NULL) {
    return _mi_malloc_generic(heap, size, zero, 0);
  }
  mi_assert_internal(block != NULL && _mi_ptr_page(block) == page);

  // pop from the free list
  page->free = mi_block_next(page, block);
  page->used++;
  [...]
```

Notice something interesting. The `page->free` pointer from `mi_page_t` structure tells mimalloc 
where exactly it should allocate the next block.
If we had control over that pointer we could allocate blocks where we want.
Lets see where that structure is in memory (pointer are different because I opened another debugger).
```
pwndbg> p page
$1 = (mi_page_t *) 0x20000000190
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
     0x20000000000      0x20040000000 rw-p 40000000      0 [anon_20000000]
    0x555555554000     0x555555555000 r--p     1000      0 chal
    0x555555555000     0x555555556000 r-xp     1000   1000 chal
    0x555555556000     0x555555557000 r--p     1000   2000 chal
```

The structure is at offset 0x190 from the start of the heap.
Thats great info, since we already have a heap leak.
Note that this info is from debug build and the structure in the original which program uses was different.
For example the pointer `&page->free` was at offset `0x190` in original one.

So the plan is to allocate a block which overlaps `&page->free` pointer and then use it to control further allocations.
We can do that easily in following steps:

1. Allocate two blocks and free the second one using `option 1`. This will put second block on `page->local_free` list.
2. Use `option 3` to gain heap leak.
3. Use `option 4` on the second one and write `heap + 0x190` which equals `&page->free`.
4. Allocate `32` more blocks using `option 1`. The last allocation will use the chunk on `page->local_free` list, which we overwrote in `3.`.
Now we can nicely overwrite the `page->free` pointer with our selected address and place blocks where we want.

Now comes the part where we leak stuff.

We have a libc leak at `heap + 0x118`.
It points to memory segment right after libc but seems to be contiguous (it worked on remote).
I dont know why, but libc segments are displayed as `ld-musl-x86_64.so.1`.
```
pwndbg> x/gx 0x20000000118
0x20000000118:  0x00007ffff7ffdb28
pwndbg> vmmap 0x00007ffff7ffdb28
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x7ffff7ffb000     0x7ffff7ffc000 rw-p     1000  a1000 ld-musl-x86_64.so.1
►   0x7ffff7ffc000     0x7ffff7fff000 rw-p     3000      0 [anon_7ffff7ffc] +0x1b28
```

Now, this is the point where I got stuck. The binary had full RELRO protection and I couldn't find a way to hijack control flow.
I found some random stack pointer somewhere in libc, but it was unreliable. The offset to the current top stack frame was different
every time.

I did not solve it in time ;(

But thanks to tips from [this](https://justinapplegate.me/2025/uiuctf-doremi/) writeup, I was able to finish my exploit.
The thing I needed was another stack pointer for which offset to the stack frame was constant.
I learned that pwndbg has a nice `p2p` command which searches for pointers from segment A to B.
Here, the last pointer most likely points to auxiliary vectors array.
```
pwndbg> p2p ld-musl-x86_64.so.1 stack
00:0000│  0x7ffff7fc8dae —▸ 0x7fffffff007f ◂— 0
00:0000│  0x7ffff7fc919e —▸ 0x7fffffff0007 ◂— 0
00:0000│  0x7ffff7fc9daa —▸ 0x7fffffff0000 ◂— 0
00:0000│  0x7ffff7fcba5e —▸ 0x7fffffff0007 ◂— 0
00:0000│  0x7ffff7ff5e2e —▸ 0x7fffffff0000 ◂— 0
00:0000│  0x7ffff7ffb888 —▸ 0x7fffffffdd80 ◂— 0x21 /* '!' */
```
I created another chunk there and leaked the stack pointer.
With this information we can look for ROP gadgets in the libc and place the ROP chain under current stack frame.
We will create one more chunk under the stack frame and write the ROP there.
In my case the return address was at offset `-0x90` from leaked stack address.

Solve script is in [asd.py](./asd.py).
