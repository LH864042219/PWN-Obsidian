[[HNCTF 2022 Week1]ezcmp | NSSCTF](https://www.nssctf.cn/problem/2929)
![[Pasted image 20240902213428.png]]
源码大概意思就是把buf里的字符串加密后存在buff中，然后自己输入一段同样长度的字符串，两者一样就可以获得shell。
难度不大，考验GDB的使用~~成功考倒我了~~，
![[Pasted image 20240902213757.png]]
buff的地址，加密前：
![[Pasted image 20240902214122.png]]
加密后：
![[Pasted image 20240902214201.png]]
把加密后的直接输入即可
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./ezcmp')
local = False
if local:
    p = process('./ezcmp')
else:
    p = remote('node5.anna.nssctf.cn', 27767)

payload = p64(0x144678aadc0e4072) + p64(0x84b6e81a4c7eb0e2) + p64(0xf426588abcee2052) + p64(0x0000c8cb2c5e90c2)
p.sendlineafter("useful", payload)
p.interactive()
```