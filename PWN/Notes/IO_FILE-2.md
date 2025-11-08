六月份开始学IO_FILE，中间经历了期末考和暑假，基本停停断断，再加上IO_FILE对于我来说各种结构体什么的新的东西有点多，一个知识点卡了一两个月，这回从头再跟一遍。
# 什么是IO_FILE
c语言中会用到大量的对文件进行操作的命令如fopen,fread,fclose等，这些流操作函数的file结构体大多数保存在堆上，其指针动态创建并由fopen()函数返回，在pwn题中，尤其是堆题中，可以覆盖堆上的file指针使其指向一个伪造的vtable结构，从而达到劫持并执行任意代码的效果，类似于之前学过的SROP和c++中的虚函数一样。在2.23中，这个结构体是_IO_FILE_plus，包含一个_IO_FILE结构体和一个指向_IO_jump_t结构体的指针
```c
struct _IO_FILE_plus
{
	_IO_FILE file;
	const struct _IO_jump_t *vtable;
};
```
vtable对应的结构体_IO_jump_t定义为:
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```
这个类似虚函数表的函数跳转表就是用于当程序对某个流进行操作时调用该流对应的跳转表中的某个函数。
```c
struct _IO_FILE {
      int _flags;
    #define _IO_file_flags _flags
 
    char* _IO_read_ptr;   /* Current read pointer */
    char* _IO_read_end;   /* End of get area. */
    char* _IO_read_base;  /* Start of putback+get area. */
    char* _IO_write_base; /* Start of put area. */
    char* _IO_write_ptr;  /* Current put pointer. */
    char* _IO_write_end;  /* End of put area. */
    char* _IO_buf_base;   /* Start of reserve area. */
    char* _IO_buf_end;    /* End of reserve area. */
    /* The following fields are used to support backing up and undo. */
    char *_IO_save_base; /* Pointer to start of non-current get area. */
    char *_IO_backup_base;  /* Pointer to first valid character of backup area */
    char *_IO_save_end; /* Pointer to end of non-current get area. */
 
    struct _IO_marker *_markers;
 
    struct _IO_FILE *_chain;
 
    int _fileno;
#if 0
    int _blksize;
#else
    int _flags2;
#endif
    _IO_off_t _old_offset;
 
#define __HAVE_COLUMN
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
进程中`FILE`结构通过`_chain`域构成一个链表，链表头部为`_IO_list_all`全局变量，默认情况下依次链接了`stderr`,`stdout`,`stdin`三个文件流，并将新建的流插入到头部，`vtable`虚表为`_IO_file_jumps`。
此外，还有`_IO_wide_data`结构体：
```c
struct _IO_wide_data
{
      wchar_t *_IO_read_ptr;   
      wchar_t *_IO_read_end;
      wchar_t *_IO_read_base;
      wchar_t *_IO_write_base;
      wchar_t *_IO_write_ptr;
      wchar_t *_IO_write_end;   
      wchar_t *_IO_buf_base;   
      wchar_t *_IO_buf_end;   
      [...]
      const struct _IO_jump_t *_wide_vtable;
};
```
还有一些宏的定义：
```c
#define _IO_MAGIC 0xFBAD0000
#define _OLD_STDIO_MAGIC 0xFABC0000
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4
#define _IO_NO_WRITES 8
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40
#define _IO_LINKED 0x80
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```
此外，许多`Pwn`题初始化的时候都会有下面三行：
```c
setvbuf(stdin, 0LL, 2, 0LL);
setvbuf(stdout, 0LL, 2, 0LL);
setvbuf(stderr, 0LL, 2, 0LL);
```
这是初始化程序的`io`结构体，只有初始化之后，`io`函数才能在程序过程中打印数据，如果不初始化，就只能在`exit`结束的时候，才能一起把数据打印出来。
# FSOP (libc  2.23 &2.24)
主要原理为劫持`vtable`与`_chain`，伪造`IO_FILE`，主要利用方式为调用`IO_flush_all_lockp()`函数触发。  
`IO_flush_all_lockp()`函数将在以下三种情况下被调用：

1. `libc`检测到**内存错误**，从而执行`abort`函数时（在`glibc-2.26`删除）。
2. 程序执行`exit`函数时。
3. 程序从`main`函数返回时。

当libc检测到内存错误时会产生下面的函数调用路径。
`malloc_printerr->__libc_message->__GT_ABort->_IO_flush_all_lockp->_IO_OVERFLOW`
源码：
```c
int _IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;
 
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
        ...
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
#endif
       )
      && _IO_OVERFLOW (fp, EOF) == EOF)   //如果输出缓冲区有数据，刷新输出缓冲区
    result = EOF;
 
 
    fp = fp->_chain; //遍历链表
    }
    [...]
}
```
可以看到，当满足：
```c
fp->_mode = 0
fp->_IO_write_ptr > fp->_IO_write_base
```
就会调用`_IO_OVERFLOW()`函数，而这里的`_IO_OVERFLOW`就是**文件流对象虚表的第四项**指向的内容`_IO_new_file_overflow`，因此在`libc-2.23`版本下可如下构造，进行`FSOP`：
```c
._chain => chunk_addr
chunk_addr
{
  file = {
    _flags = "/bin/sh\x00", //对应此结构体首地址(fp)
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x1,
      ...
      _mode = 0x0, //一般不用特意设置
      _unused2 = '\000' <repeats 19 times>
  },
  vtable = heap_addr
}
heap_addr
{
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x0,
  __overflow = system_addr,
    ...
}
```
因此这样构造，通过`_IO_OVERFLOW (fp)`，我们就实现了`system("/bin/sh\x00")`。