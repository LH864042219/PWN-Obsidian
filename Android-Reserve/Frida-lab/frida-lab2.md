![[Pasted image 20251105191341.png]]
打开毛都没有，去看代码
![[Pasted image 20251105191513.png]]
执行`get_flag`函数且输入参数为4919时即可获取flag
exp:
```js
function main(){
    Java.perform(function(){
        hookTest1();
    });
}
setImmediate(main);

function hookTest1(){
    var utils = Java.use("com.ad2001.frida0x2.MainActivity");
    utils.get_flag(4919);
}
```
手动执行`mian`方法
![[Pasted image 20251105191836.png]]
即可获取flag
![[Pasted image 20251105191847.png]]
