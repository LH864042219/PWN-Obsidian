gcc 模板.c -o test -z execstack -fno-stack-protector -no-pie -z norelro -s

# NX保护机制：
-z execstack / -z noexecstack  # (关闭 / 开启) 堆栈不可执行

Canary：(关闭 / 开启 / 全开启) 栈里插入cookie信息
!开canary好像会造成栈中局部变量的顺序有所改变
-fno-stack-protector / -fstack-protector / -fstack-protector-all

ASLR和PIE：
-no-pie / -pie   # (关闭 / 开启) 地址随机化，另外打开后会有get_pc_thunk

RELRO：
-z norelro / -z lazy / -z now   # (关闭 / 部分开启 / 完全开启) 对GOT表具有写权限

去除符号表：
-s

输出文件名：
-o filename
忽略栈溢出警告
-Wno-stringop-overflow
版本选择
-m32 / -m64

docker run --rm -v $(pwd):/src ubuntu20 gcc -o random random.c -z noexecstack -fno-stack-protector -no-pie -z norelro
