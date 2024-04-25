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

    # 1.alloc three chunk



    # 2.free two chunk to tcache



    # 3.modify the chunk pointer to fake chunk, and free the fake chunk




    # 4.alloc chunk again (and overwrite the fwd pointer of the chunk 2)




    # 5.alloc two time (the second chunk in on the target address so we can just modify its data)




    r.interactive()


if __name__ == "__main__":
    main()
