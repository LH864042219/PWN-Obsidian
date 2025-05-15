还是没想到有做misc的一天，最近做iscc做misc的时间比做pwn的时间都长，总结一下，毕竟也学了。
# 通用工具
## winhex
二进制数据查看工具，可以查看二进制数据
# ZIP
## 爆破
Advanced Archive Password Recovery(Windows)，好用的爆破工具
![[Pasted image 20250515211218.png]]
### 暴力
字面意思，纯暴力破解，题目的话没什么提示没必要用，大概率爆不出来
### 字典 
也是字面意思，还没用过，也没去收集字典
### 掩码
题目可能会给出类似 bfs??? 的格式就大概率是掩码爆破 ??? 就是要爆破的位置
## 明文攻击
明文攻击：

- 找到压缩包内其中一个已知的文件（文件大小要大于12Byte），用相同的压缩软件压缩算法去压缩无密码压缩包，得到明文。
- 通过比较两个压缩包相同位置不同的12个字节，就可以还原出3个key，绕过密码提取出所有的文件。
- 注意明文攻击需要CRC32值相同才行。
一个例子：
- 现有加密压缩包
![[Pasted image 20250515212313.png]]
- 以及一个包含测试1的伪加密的压缩包（CRC32相同，>12字节）
![[Pasted image 20250515212355.png]]
- 进行明文攻击
![[Pasted image 20250515212416.png]]
![[Pasted image 20250515212421.png]]
- 注意：当**明文的大小比较小时，或者密文过长，攻击速度会比较慢**；即使有时没有恢复密码，也可以使用明文攻击，最后点保存还是能得到压缩包里内容的。
## 伪加密
- 紫色部分从PK开始数第9位，灰色部分第6,7列，都改为0900则是伪加密。  若是没有加密的zip文件，两处标记都是00 00。
![[Pasted image 20250512095701.png]]
- 破解伪加密的zip，只要把压缩文件**目录区**的全局方式标记改为00 00即可解密
- 除windows外的系统（如kali）可直接打开伪加密压缩包
## CRC32碰撞
什么是CRC32

- CRC 本身是「冗余校验码」的意思，CRC32 则表示会产生一个 32 bit ( 8 位十六进制数) 的校验值。由于 CRC32 产生校验值时源数据块的每一个 bit (位) 都参与了计算，所以数据块中即使只有一位发生了变化，也会得到不同的 CRC32 值。
- CRC32 校验码出现在很多文件中比如 png 文件，同样 zip 中也有 CRC32 校验码。值得注意的是 zip 中的 CRC32 是未加密文件的校验值。
CRC32攻击

- 这也就导致了基于 CRC32 的攻击手法。
  文件内内容很少 (一般比赛中大多为 4 字节左右)
  加密的密码很长
- 我们不去爆破压缩包的密码，而是直接去爆破源文件的内容 (一般都是可见的字符串)，从而获取想要的信息。
一个例子：

- 我们新建一个 flag.txt，其中内容为 123，使用密码 !QAZXSW@#EDCVFR$ 去加密
![[Pasted image 20250515212802.png]]
- 我们去计算文件的 CRC32 值发现和上图中的 CRC32 值吻合
![[Pasted image 20250515212815.png]]
- 在爆破时我们所枚举的所有可能字符串的 CRC32 值是要与压缩源文件数据区中的 CRC32 值所对应
```python
# -*- coding: utf-8 -*-
import zlib
import base64
import string
import itertools
import struct

# 爆破所有可能的crc，存起来
alph = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
crcdict = {}
print("computing all possible CRCs...")
for x in itertools.product(list(alph), repeat=3):
    st = ''.join(x)
    testcrc = zlib.crc32(st.encode('utf8'))
    crcdict[testcrc] = st
print("Done!")
print(crcdict)

# 判断crc是否在集合中
f = open('flag.zip','rb')
data = f.read()
f.close()
crc = "".join('%s' %id for id in data[14:18])
if crc in crcdict:
    print(crcdict[crc])
else:
    print("FAILED!")

```
- 推荐一个好用的6位的CRC32爆破工具  
  下载：https://github.com/theonlypwner/crc32  
  使用：`python crc32.py reverse 你的crc32密文`（密文需要加上0x变成16进制）
# 图片
## binwalk(linux)
https://www.cnblogs.com/M0x1n/p/binwalk.html
文件分析工具，可以探测文件里是否有可识别的文件
## zsteg(linux)

可以检测PNG和BMP图片里的隐写数据

## foremost(linux)

# 取证分析
## volatility(linux)

# word
## 隐藏

## 压缩

# 音频
## audacity(windows)
音频波形查看工具
![[Pasted image 20250514163412.png]]

# 二维码
QR_Research(Windows)，二维码扫描工具，别的扫不出来他可以扫出来