# 什么是shellcode
shellcode通常是指一段汇编代码，在执行后可以让我们来获取shell或者直接cat flag

# 什么时候可以用shellcode
## NX
通常而言，一般的题目都会打开NX保护，即栈不可执行，如下图
![[Pasted image 20250721170343.png]]
可以看到栈(stack)部分是没有执行(x)的权限的，有执行权限的部分也没有写(w)的权限，这种情况下就无法注入shellcode来获取shell。
![[Pasted image 20250721170530.png]]
可以看到同样的代码中如果关闭NX保护，栈部分就有可执行权限，这种情况下就可以注入shellcode来执行。

## mmap
`void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);`
mmap函数是一个强大的系统调用，用于创建内存映射。它在内存管理、文件I/O和进程间通信中有广泛应用。
通常来说，在pwn题里，mmap函数用于改变一段地址的权限，通常出现在shellcode类型的题目中来改变某一段地址让其有rwx的权限来供攻击者来注入shellcode获取shell。
相同类型的函数还有mprotect等。

# 如何生成shellcode
pwntools集合了一个自动生产shellcode的函数
```
context(arch='i386', os='linux', log_level='debug')
shellcode = asm(shellcraft.sh())
```
用context.arch来设定需要生成shellcode是32位还是64位，即可自动生成一段shellcode


