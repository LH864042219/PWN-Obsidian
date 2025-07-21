# 什么是shellcode
shellcode通常是指一段汇编代码，在执行后可以让我们来获取shell或者直接cat flag

# 什么时候可以用shellcode
通常而言，一般的题目都会打开NX保护，即栈不可执行，如下图
![[Pasted image 20250721170343.png]]
可以看到栈(stack)部分是没有执行(x)的权限的，有执行权限的部分也没有写(w)的权限，这种情况下就无法注入shellcode来获取shell。
![[Pasted image 20250721170530.png]]
可以看到同样的代码中如果有sh