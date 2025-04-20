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
➜  tools protoc --version
libprotoc 3.6.1
```
## protobuf-c

Protobuf官方支持C++、C#、Dart、Go、Java、Kotlin、Python等语言，但是不支持C语言。
而CTF中的Pwn题通常由C语言编写，这就用到了一个第三方库 **protobuf-c**。
Github项目地址：[https://github.com/protobuf-c/protobuf-c](https://bbs.kanxue.com/elink@814K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6Y4K9i4c8Z5N6h3u0Q4x3X3g2U0L8$3#2Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3y4Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3x3%60.)
下载Protobuf-c项目：[https://github.com/protobuf-c/protobuf-c/releases](https://bbs.kanxue.com/elink@813K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6Y4K9i4c8Z5N6h3u0Q4x3X3g2U0L8$3#2Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3y4Q4x3V1k6H3M7X3!0@1L8$3u0#2k6W2\)9J5k6r3y4Q4x3V1k6J5k6h3I4W2j5i4y4W2M7H3%60.%60.)
进入Protobuf-c目录配置、编译并安装：
```shell
➜  tools protoc --version
libprotoc 3.6.1
```
## apt
当然也可以直接用apt安装
```shell
sudo apt install protobuf-compiler          # 安装protoc以及protobuflib
sudo apt install protobuf-c-compiler        # 安装protoc-gen-c
```
简单直接
# 基本语法

先来看一个官方文档给出的例子：
```proto
// demo.proto
syntax = "proto3";

package tutorial;

message Person {
  string name = 1;
  int32 id = 2;
  string email = 3;

  enum PhoneType {
    PHONE_TYPE_UNSPECIFIED = 0;
    PHONE_TYPE_MOBILE = 1;
    PHONE_TYPE_HOME = 2;
    PHONE_TYPE_WORK = 3;
  }

  message PhoneNumber {
    string number = 1;
    PhoneType type = 2;
  }

  repeated PhoneNumber phones = 4;
}

message AddressBook {
  repeated Person people = 1;
}
```
## syntax
syntax指明protobuf的版本，有proto2和proto3两个版本，省略默认为proto2。
```
syntax = "proto2";
syntax = "proto3";
```
## package
package可以防止命名空间冲突，简单的项目中可以省略。
```
package tutorial;
```
## message
message用于定义消息结构体，类似C语言中的struct。
每个字段包括**修饰符 类型 字段名**，并且末尾通过**等号**设置**唯一字段编号**。
修饰符包括如下几种：
- optional：可以不提供字段值，字段将被初始化为默认值。（Proto3中不允许显示声明，不加修饰符即optional）
- repeated：类似vector，表明该字段为动态数组，可重复任意次。
- required：必须提供字段值。（Proto3不再支持required）
常见的基本类型：
- bool
- in32
- float
- double
- string
# 编译

可以通过如下命令编译proto文件：
```shell
protoc -I=$SRC_DIR --c_out=$DST_DIR $SRC_DIR/demo.proto
```
- -I=$SRC_DIR用于指定源码目录，默认使用当前目录。
- --cpp_out=$DST_DIR用于指定目标代码存放位置。
因此，以上命令也可以简化为：
```shell
protoc --c_out=. demo.proto
```
这会编译生成以下两个文件：
- **demo.pb-c.h**：类的声明。
- **demo.pb-c.c**：类的实现。
CTF题目通常为C语言编写，因此为了后续逆向工作，需要理解编译后的C语言文件相关结构。
如果想要编译为Python代码，用如下命令（在CTF中通常编译为Python代码以在脚本中与程序交互）：
```shell
protoc --python_out=. demo.proto
```
会生成 **demo_pb2.py**。（pb2后缀只是为了和protobuf1区分）
# 使用

## 引入

可以直接在Python中import后调用：
```python
import demo_pb2
 
person = demo_pb2.Person()
person.id = 1234
person.name = "John Doe"
person.email = "jdoe@example.com"
 
phone = person.phones.add()
phone.number = "555-4321"
phone.type = demo_pb2.Person.PHONE_TYPE_HOME
```
## 序列化与反序列化

可以通过 **SerializeToString序列化** 或 **ParseFromString反序列化**：
```python
# Write the new address book back to disk.
with open(sys.argv[1], "wb") as f:
  f.write(demo_pb2.SerializeToString())
  
demo = demo_pb2.AddressBook()
 
# Read the existing address book.
try:
  with open(sys.argv[1], "rb") as f:
    demo_pb2.ParseFromString(f.read())
except IOError:
  print(sys.argv[1] + ": Could not open file.  Creating a new one.")
```
# 逆向分析
