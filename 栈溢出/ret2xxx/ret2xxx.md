
[9、ret2xx_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1Uv411j7fr/?p=9&spm_id_from=333.1007.top_right_bar_window_history.content.click&vd_source=5fae7a44ef30f9bc4ae07b1f5acacb41)
# ROP
在栈溢出的基础上，利用程序中已有的小片段（gadgets）来改变某些寄存器或者变量的值，从而控制程序的执行流程。

所谓gadgets就是以ret结尾的指令序列，通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程。

之所以称之为ROP，是因为利用了指令集中的ret指令，改变了指令流的执行顺序，ROP攻击一般要满足如下条件：
	**1. 程序存在溢出，并且可以控制返回地址。**
	**2. 可以找到满足条件的gadgets以及相应的gadgets的地址。**
ps:如果gadgets每次的地址不固定，那我们就需要想办法动态获得对应的地址。

# ret2text
ret2text 即控制程序执行程序本身已有的代码{.text)，我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码（也就是gadgets）
例题：[[buu jarvisoj_level2]]   [[buu jarvisoj_level2_x64]]
32位使用的是栈，64位使用寄存器，注意区别
# ret2shellcode
控制程序执行shellcode代码。
常见的一些  [[shellcode]]

exp.  [[nss [GDOUCTF 2023]Shellcode]]


# ret2syscall
控制程序执行系统调用，获取shell
由于该类题无法直接利用程序中的某一段代码或自己填写代码来获得shell，我们利用程序中的gadgets来获得shell，利用系统调用。
- 系统调用相关：[https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8](https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8)
简单地说，只要我们把对应获取shell的系统调用的参数放到对应的寄存器中，那我们在执行 int 0x80 就可以执行对应的系统调用。
比如可以利用如下的系统调用来获取shell
```python
execve("/bin/sh",NULL,NULL)
```
其中，该程序是 32 位，所以我们需要使得

- 系统调用号，即 eax 应该为 0xb
- 第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
- 第二个参数，即 ecx 应该为 0
- 第三个参数，即 edx 应该为 0

而我们如何控制这些寄存器的值 呢？这里就需要使用 gadgets。比如说，现在栈顶是 10，那么如果此时执行了 pop eax，那么现在 eax 的值就为 10。但是我们并不能期待有一段连续的代码可以同时控制对应的寄存器，所以我们需要一段一段控制，这也是我们在 gadgets 最后使用 ret 来再次控制程序执行流程的原因。具体寻找 gadgets 的方法，我们可以使用 ropgadgets 这个工具。