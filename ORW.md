ORW(open,read,write)类的题目一般出现在开启了sandbox的题目中。这类题目通常会禁用一些系统调用(例如execve之类的)，但一般会保留orw中的一些，虽然我们无法获取shell,但这时候我们可以利用这些系统调用来直接读取flag并输出。
orw的构造方法一般有两种，一种是ROP链型，这需要足够的读入长度以及足够使用的gadgets；另一种则是shellcode型的，这种情况下读入长度会短一些，但需要有可执行的地址，通常伴随着mmap函数。
这里先给出一些常见函数及其参数：
```
mov rax, 2          ; 系统调用号 2 (sys_open)
mov rdi, filename   ; 文件名的指针
mov rsi, O_RDONLY   ; 打开文件的标志
syscall             ; 调用系统调用

mov rax, 257        ; 系统调用号 257 (sys_openat)
mov rdi, -100       ; AT_FDCWD
mov rsi, pathname   ; 文件路径的指针
mov rdx, O_CREAT | O_WRONLY ; 打开文件的标志
mov r10, 0644       ; 文件权限
syscall             ; 调用系统调用
```
```
mov rax, 0          ; 系统调用号 0 (sys_read)
mov rdi, 0          ; 文件描述符 0 (stdin)
mov rsi, buffer     ; 缓冲区指针
mov rdx, 100        ; 要读取的字节数
syscall             ; 调用系统调用

mov rax, 17         ; 系统调用号 17 (sys_pread)
mov rdi, fd         ; 文件描述符
mov rsi, buffer     ; 缓冲区指针
mov rdx, 100        ; 要读取的字节数
mov r10, offset     ; 读取的起始位置
syscall             ; 调用系统调用

mov rax, 19         ; 系统调用号 19 (sys_readv)
mov rdi, fd         ; 文件描述符
mov rsi, iov        ; iovec 结构体数组的指针
mov rdx, iovcnt     ; iovec 结构体的数量
syscall             ; 调用系统调用

mov rax, 295        ; 系统调用号 295 (sys_preadv)
mov rdi, fd         ; 文件描述符
mov rsi, iov        ; iovec 结构体数组的指针
mov rdx, iovcnt     ; iovec 结构体的数量
mov r10, offset     ; 读取的起始位置
syscall             ; 调用系统调用
```
```
mov rax, 1          ; 系统调用号 1 (sys_write)
mov rdi, 1          ; 文件描述符 1 (stdout)
mov rsi, message    ; 缓冲区指针
mov rdx, 13         ; 要写入的字节数
syscall             ; 调用系统调用

mov rax, 18         ; 系统调用号 18 (sys_pwrite)
mov rdi, fd         ; 文件描述符
mov rsi, buffer     ; 缓冲区指针
mov rdx, 100        ; 要写入的字节数
mov r10, offset     ; 写入的起始位置
syscall             ; 调用系统调用

mov rax, 20         ; 系统调用号 20 (sys_writev)
mov rdi, fd         ; 文件描述符
mov rsi, iov        ; iovec 结构体数组的指针
mov rdx, iovcnt     ; iovec 结构体的数量
syscall             ; 调用系统调用

mov rax, 296        ; 系统调用号 296 (sys_pwritev)
mov rdi, fd         ; 文件描述符
mov rsi, iov        ; iovec 结构体数组的指针
mov rdx, iovcnt     ; iovec 结构体的数量
mov r10, offset     ; 写入的起始位置
syscall             ; 调用系统调用
```
```

```