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
## Protobuf关键结构体

在生成的demo-pb-c.c文件中，可以发现存在unpack函数：
```c
Tutorial__AddressBook * tutorial__address_book__unpack(ProtobufCAllocator *allocator, size_t len, const uint8_t *data)
{
  return (Tutorial__AddressBook *)
     protobuf_c_message_unpack (&tutorial__address_book__descriptor,
                                allocator, len, data);
}
```
这个反序列化函数传入描述**消息结构体数据**的**descriptor**。我们可以在IDA中分析descriptor还原消息结构体。

### Descriptor结构体

Descriptor定义如下：
```c
struct ProtobufCMessageDescriptor {
    /** Magic value checked to ensure that the API is used correctly. */
    uint32_t            magic;
    /** The qualified name (e.g., "namespace.Type"). */
    const char          *name;
    /** The unqualified name as given in the .proto file (e.g., "Type"). */
    const char          *short_name;
    /** Identifier used in generated C code. */
    const char          *c_name;
    /** The dot-separated namespace. */
    const char          *package_name;
    /**
     * Size in bytes of the C structure representing an instance of this
     * type of message.
     */
    size_t              sizeof_message;
    /** Number of elements in `fields`. */
    unsigned            n_fields;
    /** Field descriptors, sorted by tag number. */
    const ProtobufCFieldDescriptor  *fields;
    /** Used for looking up fields by name. */
    const unsigned          *fields_sorted_by_name;
    /** Number of elements in `field_ranges`. */
    unsigned            n_field_ranges;
    /** Used for looking up fields by id. */
    const ProtobufCIntRange     *field_ranges;
    /** Message initialisation function. */
    ProtobufCMessageInit        message_init;
    /** Reserved for future use. */
    void                *reserved1;
    /** Reserved for future use. */
    void                *reserved2;
    /** Reserved for future use. */
    void                *reserved3;
};
```
我们需要关注的有几个重要字段：
- magic：通常为0x28AAEEF9。
- n_fields：结构体中的字段数量。
- fields：指向一个储存字段和数据的结构体。
fields是ProtobufCFieldDescriptor类型。
### ProtobufCFieldDescriptor结构体

我们看一下它的定义：
```c
struct ProtobufCFieldDescriptor {
    /** Name of the field as given in the .proto file. */
    const char      *name;
    /** Tag value of the field as given in the .proto file. */
    uint32_t        id;
    /** Whether the field is `REQUIRED`, `OPTIONAL`, or `REPEATED`. */
    ProtobufCLabel      label;
    /** The type of the field. */
    ProtobufCType       type;
    /**
     * The offset in bytes of the message's C structure's quantifier field
     * (the `has_MEMBER` field for optional members or the `n_MEMBER` field
     * for repeated members or the case enum for oneofs).
     */
    unsigned        quantifier_offset;
    /**
     * The offset in bytes into the message's C structure for the member
     * itself.
     */
    unsigned        offset;
    /**
     * A type-specific descriptor.
     *
     * If `type` is `PROTOBUF_C_TYPE_ENUM`, then `descriptor` points to the
     * corresponding `ProtobufCEnumDescriptor`.
     *
     * If `type` is `PROTOBUF_C_TYPE_MESSAGE`, then `descriptor` points to
     * the corresponding `ProtobufCMessageDescriptor`.
     *
     * Otherwise this field is NULL.
     */
    const void      *descriptor; /* for MESSAGE and ENUM types */
 
    /** The default value for this field, if defined. May be NULL. */
    const void      *default_value;
 
    /**
     * A flag word. Zero or more of the bits defined in the
     * `ProtobufCFieldFlag` enum may be set.
     */
    uint32_t        flags;
 
    /** Reserved for future use. */
    unsigned        reserved_flags;
    /** Reserved for future use. */
    void            *reserved2;
    /** Reserved for future use. */
    void            *reserved3;
};
```
我们需要关注的有：
- name：字段名。
- id：唯一字段编号。
- label：修饰符，如：required、optional、repeated。
- type：数据类型，如：bool、int32、float、double等。
### label和type
label和type都是枚举类型，我们看一下它的定义：
```c
typedef enum {
    /** A well-formed message must have exactly one of this field. */
    PROTOBUF_C_LABEL_REQUIRED,
 
    /**
     * A well-formed message can have zero or one of this field (but not
     * more than one).
     */
    PROTOBUF_C_LABEL_OPTIONAL,
 
    /**
     * This field can be repeated any number of times (including zero) in a
     * well-formed message. The order of the repeated values will be
     * preserved.
     */
    PROTOBUF_C_LABEL_REPEATED,
 
    /**
     * This field has no label. This is valid only in proto3 and is
     * equivalent to OPTIONAL but no "has" quantifier will be consulted.
     */
    PROTOBUF_C_LABEL_NONE,
} ProtobufCLabel;
```
```c
typedef enum {
    PROTOBUF_C_TYPE_INT32,      /**< int32 */
    PROTOBUF_C_TYPE_SINT32,     /**< signed int32 */
    PROTOBUF_C_TYPE_SFIXED32,   /**< signed int32 (4 bytes) */
    PROTOBUF_C_TYPE_INT64,      /**< int64 */
    PROTOBUF_C_TYPE_SINT64,     /**< signed int64 */
    PROTOBUF_C_TYPE_SFIXED64,   /**< signed int64 (8 bytes) */
    PROTOBUF_C_TYPE_UINT32,     /**< unsigned int32 */
    PROTOBUF_C_TYPE_FIXED32,    /**< unsigned int32 (4 bytes) */
    PROTOBUF_C_TYPE_UINT64,     /**< unsigned int64 */
    PROTOBUF_C_TYPE_FIXED64,    /**< unsigned int64 (8 bytes) */
    PROTOBUF_C_TYPE_FLOAT,      /**< float */
    PROTOBUF_C_TYPE_DOUBLE,     /**< double */
    PROTOBUF_C_TYPE_BOOL,       /**< boolean */
    PROTOBUF_C_TYPE_ENUM,       /**< enumerated type */
    PROTOBUF_C_TYPE_STRING,     /**< UTF-8 or ASCII string */
    PROTOBUF_C_TYPE_BYTES,      /**< arbitrary byte sequence */
    PROTOBUF_C_TYPE_MESSAGE,    /**< nested message */
} ProtobufCType;
```
# 例题
这里用XYCTF的bot作为例题
![[Pasted image 20250420144800.png]]
首先我们可以找到他有unpack函数以及descriptor结构体
![[Pasted image 20250420145311.png]]
结构体中我们可以看出message_request结构有5个字段，后面的fields指向的就是储存字段和数据的结构体。
![[Pasted image 20250420145501.png]]
例如第一个字段名为id，后面的1, 0, 0分别为id, label, type。
这里放出剩下四个字段
![[Pasted image 20250420145654.png]]![[Pasted image 20250420145704.png]]
经过查询可以得出该结构体的样子
```proto
syntax = "proto2";

message message_request{
    required int32 id = 1;
    required string sender = 2;
    required uint32 len = 3;
    required bytes content = 4;
    required int32 actionid = 5;
}
```
syntax的版本需查看ProtobufCFieldDescriptor结构体中是否有default_value字段，proto3中删除了default_value字段，可以根据字段数量来判断proto版本。
有了proto后将其编译，可以得到一个py文件，然后就可以在exp中引用他来和程序交互了
```python
from pwn import *
import de_pb2

def edit(id, len, content):
	message = de_pb2.message_request()
	message.sender = 'admin'
	message.len = len
	message.content = content
	message.actionid = 1
	message.id = id
	data = message.SerializeToString()
	p.sendafter(b'TESTTESTTEST!', data)

def show(id):
	message = de_pb2.message_request()
	message.sender = 'admin'
	message.len = 1
	message.content = b'hello'
	message.actionid = 2
	message.id = id
	data = message.SerializeToString()
	p.sendafter(b'TESTTESTTEST!', data)

debug()
edit(0, 8, b'deadbeef')
edit(1, 8, b'deadbeef')
show(2)
```