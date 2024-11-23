```
命令: ROPgadget --binary 文件名 --only "pop|ret" | grep rdi
命令: ROPgadget --binary 文件名 --only "pop|ret" | grep rsi
命令: ROPgadget --binary 文件名 --only "pop|ret"
命令: ROPgadget --binary 文件名  --only 'int'   查找有int 0x80的地址
```

还可以查找一些字符串的地址
```
命令: ROPgadget --binary 文件名 --string '/bin/sh'

命令: ROPgadget --binary 文件名 --string '/sh'

命令: ROPgadget --binary 文件名 --string 'sh'

命令: ROPgadget --binary 文件名 --string 'cat flag'

命令: ROPgadget --binary 文件名 --string 'cat flag.txt'
```

