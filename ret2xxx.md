# ret2text

# ret2shellcode

# ret2system

# ret2syscall

# ret2csu

# ret2dlresolve
ret2dlresolve 是栈溢出下的一种攻击方法，主要用于程序没有办法利用 puts 、printf、writer 函数等泄露程序内存信息的情况。
## 延迟绑定
我们都知道，在 Linux 中，为了程序运行的效率与性能，在没有开启 FULL RELRO 时候，程序在第一次执行函数时，会先执行一次动态链接，将对应函数的 got 表填上 libc 中的函数地址。在这个过程中，程序使用 _dl_runtime_resolve(link_map_obj, realoc_index) 来对动态链接的函数进行重定位。

以 32 位程序为例，如图
![[Pasted image 20250420100625.png]]
可以看到在 read@plt 中时会利用jmp跳转到 0x804a010 ，即
![[Pasted image 20250420100956.png]]
也可以看到在绑定前 read@got 里存放的不是 read 直接地址，而是 read@plt 的后续语句 0x8048396
![[Pasted image 20250420101230.png]]
接着压入两个参数（8, dword ptr [0x804a004]），分别是 `reloc_offset` 和 `link_map_obj` 参数，然后就会进入` _dl_runtime_resolve` 函数，执行完后就会将read@got > read@libc，之后这个位置就是read的实际地址了，第二次调用时也不需要再执行` _dl_runtime_resolve` 函数。

其中 link_map_obj 参数的作用是为了能够定位 .dynamic 段，而定位了 .dynamic 段就能接着定位(根据偏移）到 .dynstr 段、.dynsym 段、.rel.plt 段，该参数是 PLT0 默认提供的，程序中所有函数在动态链接过程中的该参数都是相同的；
而 reloc_offset 是对应函数的 plt 提供的，起到定位对应函数的 ELF_Rel 结构体的作用。
![[Pasted image 20250420102830.png]]
通过上图我们可以看到 plt 中的各个函数的 push 的值都是不同的，也就是说 reloc_index 的值是不同的。从图中可以看到，plt 段开头就是 PLT0。

接下来我们介绍下 .dynstr 段、.dynsym 段、.rel.plt 段。

通过以下命令可以找出各个段的地址
```shell
objdump -s -j .dynsym pwn
```
.dynsym 段：由 Elf_Sym 结构体集合而成
![[Pasted image 20250420102501.png]]
其中的 Elf_Sym 结构体如代码
```
typedef struct {
    ELF32_Word st_name;
    ELF32_Addr st_value;
    ELF32_Word st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Section st_shndx;
} Elf32_Sym;
```
其中 st_name 域是相对于 .dynstr 段的偏移，来确定函数名称字符串在 .dynstr 段的地址；st_value 域是当前符合被导出时存放虚拟地址的。

.dynstr 段：存放了各个函数的名称字符串。
![[Pasted image 20250420102516.png]]
.rel.plt 段：由 Elf_Rel 结构体集合而成
![[Pasted image 20250420103353.png]]其中的 Elf_Rel 结构体如代码
```c
typedef struct {
    ELF32_Addr r_offset;
    ELF32_Addr r_info;
} Elf32_Rel;
```
r_offset 域用于保存解析后的符号地址写入内存的位置， r_info 域的值在 右移 8 位之后的值用于标识该符号在 .dynsym 段中的位置，也就是确定该函数的 Elf_Sym 结构体地址。其中的 r_offset 域也就是 GOT 表，当解析完成后，GOT 表中对应的函数地址也就被写上了对应函数的 libc 地址。

其中，这几个段的关系是这样的。

通过 link_map_obj 参数定位 .dynamic 段，再根据偏移定位到 .dynstr 段、.dynsym 段、.rel.plt 段后，再通过 reloc_offset + .rel.plt 确定了 .rel.plt 段中对应函数的 Elf.Rel 结构体后，就能确定其中的 r_offset 也就是对应函数的 GOT 表地址，还有 r_info，根据 (r_info >> 8) + .dynsym 确定对应函数在 .dynsym 段中的 Elf_Sym 结构体，那么我们又获得了 st_name ，根据 st_name + .dynstr 来确定对应函数的名称字符串地址，最后，根据获得的函数名字符串来在 libc 中寻找对应函数的 libc 地址，再返回写在 got 表上。