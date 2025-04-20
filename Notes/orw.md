# 介绍 
`ORW(open,read,write)`类的题目一般出现在开启了`sandbox`的题目中。这类题目通常会禁用一些系统调用(例如`execve`之类的)，但一般会保留`orw`中的一些，虽然我们无法获取`shell`,但这时候我们可以利用这些系统调用来直接读取`flag`并输出。
`orw`的构造方法一般有两种，一种是ROP链型，这需要足够的读入长度以及足够使用的`gadgets`；另一种则是`shellcode`型的，这种情况下读入长度会短一些，但需要有可执行的地址，通常伴随着`mmap`函数。
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
mov rax, 9          ; 系统调用号 9 (sys_mmap)
mov rdi, 0          ; addr = NULL
mov rsi, 4096       ; length = 4096
mov rdx, PROT_READ | PROT_WRITE ; prot = PROT_READ | PROT_WRITE
mov r10, MAP_PRIVATE | MAP_ANONYMOUS ; flags = MAP_PRIVATE | MAP_ANONYMOUS
mov r8, -1          ; fd = -1
mov r9, 0           ; offset = 0
syscall             ; 调用系统调用

mov rax, 10         ; 系统调用号 10 (sys_mprotect)
mov rdi, addr       ; addr = 内存区域的起始地址
mov rsi, 4096       ; len = 内存区域的长度
mov rdx, PROT_READ  ; prot = 新的保护标志
syscall             ; 调用系统调用
```
```
mov rax, 40         ; 系统调用号 40 (sys_sendfile)
mov rdi, out_fd     ; 目标文件描述符
mov rsi, in_fd      ; 源文件描述符
mov rdx, 0          ; 偏移量的指针 (NULL)
mov r10, 1024       ; 要发送的字节数
syscall             ; 调用系统调用

mov rax, 187        ; 系统调用号 187 (sys_sendfile64)
mov rdi, out_fd     ; 目标文件描述符
mov rsi, in_fd      ; 源文件描述符
mov rdx, 0          ; 偏移量的指针 (NULL)
mov r10, 1024       ; 要发送的字节数
syscall             ; 调用系统调用
```
# 例题

# 特殊
## orw缺w
这种情况下，若是找不到任何可以用于替代`write`的函数，则可以使用侧信道爆破的方法来逐位爆破出`flag`的值