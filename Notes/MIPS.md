XYCTF的EZ3.0 [XYCTF-PWN-CrazyCat](https://hnusec-team.feishu.cn/docx/IadwdxucBoVZ0FxnlLJcFmXOnvd#share-CfQrdo2gMowMh3xsYz3cYh2Hnbe)

# 环境安装与调试

MIPS是一个架构，与x86, x86-64有很大的区别

首先下载依赖库和qemu

```Shell
sudo apt-get install gcc-mips-linux-gnu
sudo apt-get install gcc-mipsel-linux-gnu
sudo apt-get install gcc-mips64-linux-gnuabi64
sudo apt-get install gcc-mips64el-linux-gnuabi64
sudo apt-get install qemu
sudo apt-get install qemu-user
sudo apt-get install qemu-user-static
sudo apt-get install qemu-system
sudo apt-get install gdb-multiarch
```

因为用的是MIPS架构，需要用qemu来作为一个虚拟环境来运行文件

```Shell
qume-mipsel -L /usr/mipsel-linux-gnu/ your_file_name
# -L 后面跟的是刚刚下载的mips的依赖库，根据文件版本选择小端序(mipsel)还是大端序(mips)
# 加上 -g port 可以进入进入gdb调试
qume-mipsel -g 1234  -L /usr/mipsel-linux-gnu/ your_file_name
gdb-multiarch your_file_name
> target remote localhost:1234
```

# MIPS基础知识

## 寄存器

MIPS架构有32个寄存器

![](https://hnusec-team.feishu.cn/space/api/box/stream/download/asynccode/?code=MmQ5OWFlZmE5MGI0YjkwNjdlMmUxYmRjNWQxMThjMjNfQjVGUU0xZGVGWERlZnV0dmhFelNDRGx4MWhRY0l5MmZfVG9rZW46UEN1cWJyVmRGb0lLZER4OFpVM2NoN0hQbjYzXzE3NDUxMzc2NzU6MTc0NTE0MTI3NV9WNA)

## 常用指令

- li(Load Immediate)：
    

用于将一个最大16位立即数 存入一个寄存器

```Plain
li $Rd, imm
```

- lui(Load Upper halfword Immediate)：
    

读取一个16位立即数放入寄存器的高16位，低16位补0。如果加载一个32位立即数（DWORD）则需要lui和addi两条指令配合完成。因为作为32位定长指令没有足够的空间存储32位立即数，只能用16位代替。

```Plain
lui $a1, 0x42 //将0x42放入$a1的高16位
```

- lw(Load Word)：
    

用于从一个指定的地址加载一个word类型的值到寄存器中

```Plain
lw $Rt, offset($Rs)
lw $s0, 0($sp) 
//取堆栈地址偏移0内存word长度的值到$s0中，$s0 = MEM[$sp+0]
```

- sw(Load Word)：
    

用于将源寄存器中的值存入指定的地址

```Plain
sw $Rt, offset($Rs)
sw $a0, 0($sp) 
//将$a0寄存器中的一个word大小的值存入堆栈，且$sp自动抬栈
```

- 算术指令
    

```Plain
add $t0, $t1, $t2 //$t0 = $t1 + $t2，带符号数相加
sub $t0, $t1, $t2 //$t0 = $t1 - $t2，带符号数相减
addi $t0, $t1, 5 //$t0 = $t1 + 5
addu $t0, $t1, $t2 //$t0 = $t1 + $t2，无符号数相加
subu $t0, $t1, $t2 //$t0 = $t1 - $t2，无符号数相减
mult $t3, $t4 //(Hi, Lo) = $t3 * $t4
div $t5, $t6 //$Lo = $t5 / $t6 $Lo为商的整数部分， $Hi为商的余数部分
mfhi $t0 //$t0 = $Hi
mflo $t1 //$t1 = $Lo
```

- 直接跳转指令
    

j：该指令无条件跳转到一个绝对地址。实际上，j 指令跳转到的地址并不是直接指定32位的地址（所有 MIPS 指令都是 32 位长，不可能全部用于编址数据域，那样的指令是无效的，也许只有nop）：由于目的地址的最高4位无法在指令的编码中给出，32位地址的最高4位取值当前PC的最高4位。对于一般的程序而言，28位地址所支持的256MB跳转空间已经足够大了。

要实现更远程的跳转，必须使用 jr 指令跳转到指定寄存器中，该指令也用于需要计算合成跳转目标地址的情形。你可以使用 j 助记符后面紧跟一个寄存器表示寄存器跳转，不过一般不推荐这么做。

jal、jalr：这两条指令分别实现了直接和间接子程序调用。在跳转到指定地址实现子程序调用的同时，需要将返回地址（当前指令地址+8）保存到 ra（$31）寄存器中。为什么是当前指令地址加8呢？这是因为紧随跳转指令之后有一条立即执行的延迟槽指令（例如nop占位指令），加8刚好是延迟槽后面的那条有效指令。从子程序返回是通过寄存器跳转完成，通常调用 jr ra。

基于 PC 相对寻址的位置无关子程序调用通过 bal、bgezal 和 bltzal 指令完成。条件分支和链接指令即使在条件为假的情况下，也会将它们的返回地址保存到 ra 中，这在需要基于当前指令地址做计算的场合非常有用。

b：相对当前指令地址（PC）的无条件短距离跳转指令。

bal：基于当前指令地址（PC）的函数调用指令。

## 系统调用

系统调用号存放在$v0中,参数存放在$a0~$a3中（如果参数过多，会有另一套机制来处理）,系统调用的返回值通常放在$v0中,如果系统调用出错，则会在$a3中返回一个错误号,最终调用Syscall指令。

## MIPS延迟绑定

如何找到got表？

```Plain
lui        gp,0x42
addiu      gp,gp,-0x7510
...............
lw      v0,-0x7fac (gp)   =>->puts     = 0x0400a00  
or       t9,v0,zero  
jalr       t9   =>puts
```

通过gp全局指针寄存器，根据偏移0x7fac定位到puts函数的got表地址，然后再用lw指令取出里面的地址跳去执行。由于puts函数第一次调用还没有初始化，所以跳去的地址也就是puts_plt.又称.MIPS.stubs段

```Plain
0x0400a00<puts_plt> lw  $t9, -0x7ff0($gp)  =>_dl_runtime_resolve
0x0400a04 <puts_plt+4>         move   $t7, $ra 
0x0400a08 <puts_plt+8>         jalr   $t9          
0x0400a0c <puts_plt+12>        li        t8,0x15
```

先取出got开始位置处的_dl_runtime_resolve函数指针（程序初始化时被装载），然后保存返回地址到t7，将当前函数的reloc索引放入t8，跳去执行_dl_runtime_resolve。

# 总结

总体而言除了指令和寄存器不同，做题思路和以前学过的架构没什么太大区别，都是找有用的gadgets构造ROP，再或者就是哪天遇到题目需要手写shellcode再说了。