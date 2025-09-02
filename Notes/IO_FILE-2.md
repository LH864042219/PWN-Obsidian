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

