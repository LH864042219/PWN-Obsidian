# 概念
[Protocol Buffers Wiki](https://zh.wikipedia.org/wiki/Protocol_Buffers)
protobuf就是一种google开发的一种可以跨平台的数据结构协议，用这个可以实现多平台共用一个数据结构而无需每种语言都写。

在pwn题中，我们需要先逆向分析得到Protobuf结构体，然后构造序列化后的Protobuf与程序交互

# 安装
## protobuf

官方GitHub地址：[https://github.com/protocolbuffers/protobuf](https://bbs.kanxue.com/elink@e31K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6Y4K9i4c8Z5N6h3u0Q4x3X3g2U0L8$3#2Q4x3V1k6H3M7X3!0@1L8$3y4G2L8r3u0#2k6X3k6W2M7Y4y4Q4x3V1k6H3M7X3!0@1L8$3u0#2k6R3%60.%60.)
需要安装 **Protobuf运行时** 和 **协议编译器（用于编译.proto文件）**。
下载Protobuf项目（不要下载版本太高的，否则后面的protobuf-c无法安装）：
```shell
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protobuf-cpp-3.6.1.tar.gz
```
解压并进入Protobuf目录：
```shell
tar -xzvf protobuf-cpp-3.6.1
cd protobuf-3.6.1
```
配置、编译并安装
```python
./configure
make
sudo make install
```
此时，输入protoc命令会报错：
```python
➜  protobuf-3.6.1 protoc --version                                                                         protoc: error while loading shared libraries: libprotoc.so.17: cannot open shared object file: No such file or directory
```
原因是因为probuf默认安装路径是/usr/local/lib，而在Ubuntu中这个路径不在LD_LIBRARY_PATH 中。

因此，需要在/usr/lib中创建软连接：
```python
cd /usr/lib
sudo ln -s /usr/local/lib/libprotoc.so.17 libprotobuf.so.17
sudo ln -s /usr/local/lib/libprotoc.so.17 libprotoc.so.17
```
再次输入protoc命令，发现正常打印版本号：
```python

```
## protobuf-c

Protobuf官方支持C++、C#、Dart、Go、Java、Kotlin、Python等语言，但是不支持C语言。

而CTF中的Pwn题通常由C语言编写，这就用到了一个第三方库 **protobuf-c**。

Github项目地址：[https://github.com/protobuf-c/protobuf-c](https://bbs.kanxue.com/elink@814K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6Y4K9i4c8Z5N6h3u0Q4x3X3g2U0L8$3#2Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3y4Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3x3%60.)

下载Protobuf-c项目：[https://github.com/protobuf-c/protobuf-c/releases](https://bbs.kanxue.com/elink@813K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6Y4K9i4c8Z5N6h3u0Q4x3X3g2U0L8$3#2Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3y4Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3y4Q4x3V1k6J5k6h3I4W2j5i4y4W2M7H3%60.%60.)

进入Protobuf-c目录配置、编译并安装：

|   |   |
|---|---|
|1<br><br>2<br><br>3<br><br>4|`tar` `-xzvf protobuf-c.``tar``.gz`<br><br>`cd` `protobuf-c`<br><br>`.``/configure` `&&` `make`<br><br>`sudo` `make` `install`|