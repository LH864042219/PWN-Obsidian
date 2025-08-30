# 基础知识
## Operating System Kernel
操作系统内核(Operation System Kernel)本质上也是一种软件，可以看作是普通应用程式与硬件之间的一层中间层，其主要作用便是调度系统资源、控制 IO 设备、操作网络与文件系统等，并为上层应用提供便捷、抽象的应用接口。
![[Pasted image 20250830152853.png]]
操作系统内核实际上是我们抽象出来的一个概念，本质上与用户进程一般无二，都是位于物理内存中的代码 + 数据，不同之处在于当 CPU 执行操作系统内核代码时通常运行在高权限，拥有着完全的硬件访问能力，而 CPU 在执行用户态代码时通常运行在低权限环境，只拥有部分 / 缺失硬件访问能力。

这两种不同权限的运行状态实际上是通过硬件来实现的，因此这里我们开始引入新的一个概念——**分级保护环**。
## hierarchical protection domains
**分级保护域**（hierarchical protection domains）又被称作保护环，简称 Rings ，是一种将计算机不同的资源划分至不同权限的模型。
在一些硬件或者微代码级别上提供不同特权态模式的 CPU 架构上，保护环通常都是硬件强制的。Rings 是从最高特权级（通常被叫作 0 级）到最低特权级（通常对应最大的数字）排列的。
Intel 的 CPU 将权限分为四个等级：Ring0、Ring1、Ring2、Ring3，权限等级依次降低，现代操作系统模型中我们通常只会使用 ring0 和 ring3，对应操作系统内核与用户进程，即 CPU 在执行用户进程代码时处在 ring3 下。
![[Pasted image 20250830153000.png]]
现在我们给【用户态】与【内核态】这两个概念下定义：
- 用户态：CPU 运行在 ring3 + 用户进程运行环境上下文。
- 内核态：CPU 运行在 ring0 + 内核代码运行环境上下文。
## 状态切换
CPU 在不同的特权级间进行切换主要有两个途径：

- 中断与异常（interrupt & exception）：当 CPU 收到一个中断 / 异常时，会切换到 ring0，并根据中断描述符表索引对应的中断处理代码以执行。
- 特权级相关指令：当 CPU 运行这些指令时会发生运行状态的改变，例如 iret 指令（ring0->ring3）或是 sysenter 指令（ring3->ring0）。

基于这些特权级切换的方式，现代操作系统的开发者包装出了系统调用（syscall），作为由 “用户态” 切换到 “内核态” 的入口，从而执行内核代码来完成用户进程所需的一些功能。当用户进程想要请求更高权限的服务时，便需要通过由系统提供的应用接口，使用系统调用以陷入内核态，再由操作系统完成请求。
### user space to kernel space （系统调用

当发生 `系统调用`，`产生异常`，`外设产生中断` 等事件时，会发生用户态到内核态的切换，进入到内核相对应的处理程序中进行处理。

系统调用是内核与用户通信的直接接口，因此我们主要关注用户空间比较常用的系统调用这一行为，其具体的过程为：

> 注意：当系统调用指令执行后，CPU 便进入内核态，以下操作在内核态完成。

1. 通过 `swapgs` 切换 GS 段寄存器，将 GS 寄存器值和一个特定位置的值进行交换，目的是保存 GS 值，同时将该位置的值作为内核执行时的 GS 值使用。
2. 将当前栈顶（用户空间栈顶）记录在 CPU 独占变量区域里，将 CPU 独占区域里记录的内核栈顶放入 rsp/esp。
3. 通过 push 保存各寄存器值，具体的代码如下:
```
ENTRY(entry_SYSCALL_64) 
/* SWAPGS_UNSAFE_STACK是一个宏，x86直接定义为swapgs指令 */ 
SWAPGS_UNSAFE_STACK 

/* 保存栈值，并设置内核栈 */
movq %rsp, PER_CPU_VAR(rsp_scratch) 
movq PER_CPU_VAR(cpu_current_top_of_stack), %rsp 


/* 通过push保存寄存器值，形成一个pt_regs结构 */ 
/* Construct struct pt_regs on stack */ 
pushq $__USER_DS                  /* pt_regs->ss */ 
pushq PER_CPU_VAR(rsp_scratch)    /* pt_regs->sp */ 
pushq %r11                        /* pt_regs->flags */ 
pushq $__USER_CS                  /* pt_regs->cs */ 
pushq %rcx                        /* pt_regs->ip */ 
pushq %rax                        /* pt_regs->orig_ax */ 
pushq %rdi                        /* pt_regs->di */ 
pushq %rsi                        /* pt_regs->si */ 
pushq %rdx                        /* pt_regs->dx */ 
pushq %rcx tuichu                 /* pt_regs->cx */ 
pushq $-ENOSYS                    /* pt_regs->ax */ 
pushq %r8                         /* pt_regs->r8 */ 
pushq %r9                         /* pt_regs->r9 */ 
pushq %r10                        /* pt_regs->r10 */ 
pushq %r11                        /* pt_regs->r11 */ 
sub $(6*8), %rsp                  /* pt_regs->bp, bx, r12-15 not saved */
```
4. 通过汇编指令判断是否为 `x32_abi`。
5. 通过系统调用号，跳到全局变量 `sys_call_table` 相应位置继续执行系统调用。

### kernel space to user space[¶](https://ctf-wiki.org/pwn/linux/kernel-mode/basic-knowledge/#kernel-space-to-user-space "Permanent link")

退出时，流程如下：

1. 通过 `swapgs` 恢复 GS 值。
2. 通过 `sysretq` 或者 `iretq` 恢复到用户控件继续执行。如果使用 `iretq` 还需要给出用户空间的一些信息（CS, eflags/rflags, esp/rsp 等）。