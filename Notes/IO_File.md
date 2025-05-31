https://bbs.kanxue.com/thread-273418.htm
https://bbs.kanxue.com/thread-272098.htm
# IO_FILE相关结构体
IO_FILE_plus结构体的定义为
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
这个函数表中有`19`个函数，分别完成`IO`相关的功能，由`IO`函数调用，如`fwrite`最终会调用`__write`函数，`fread`会调用`__doallocate`来分配`IO`缓冲区等。
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
```
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
