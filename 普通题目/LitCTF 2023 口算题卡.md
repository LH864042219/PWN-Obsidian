[[LitCTF 2023]口算题卡 | NSSCTF](https://www.nssctf.cn/problem/3876)
![[Pasted image 20240901115618.png]]
有点python基础，会用pwntools就能做
exp:
```python
from pwn import *

p = remote("node4.anna.nssctf.cn", 28420)
sign = ['+', '-']

p.recvuntil(b"fun!\n")
  
for i in range(100):
    word = str(p.recvline())[10:-4].split(' ')
    print(i, word)
    count1,count2 = word[0], word[2]
    if word[1] == '+':
        p.sendline(str(int(count1) + int(count2)))
    else:
        p.sendline(str(int(count1) - int(count2)))
    p.recvuntil(b'Correct!\n')
p.interactive()
```