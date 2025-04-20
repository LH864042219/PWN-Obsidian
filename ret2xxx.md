# ret2dlresolve
ret2dlresolve 是栈溢出下的一种攻击方法，主要用于程序没有办法利用 puts 、printf、writer 函数等泄露程序内存信息的情况。
## 延迟绑定
我们都知道，在 Linux 中，为了程序运行的效率与性能，在没有开启 FULL RELRO 时候，程序在第一次执行函数时，会先执行一次动态链接，将对应函数的 got 表填上 libc 中的函数地址。