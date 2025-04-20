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
接着压入两个参数（8, dword ptr [0x804a004]），分别是 reloc_offset 和 l