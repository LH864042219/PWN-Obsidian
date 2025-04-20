# 概念
[Protocol Buffers Wiki](https://zh.wikipedia.org/wiki/Protocol_Buffers)
protobuf就是一种google开发的一种可以跨平台的数据结构协议，用这个可以实现多平台共用一个数据结构而无需每种语言都写。

在pwn题中，我们需要先逆向分析得到Protobuf结构体，然后构造序列化后的Protobuf与程序交互

# 安装

