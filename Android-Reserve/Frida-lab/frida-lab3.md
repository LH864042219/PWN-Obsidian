![[Pasted image 20251105192005.png]]
直接查看代码，可以看到当`Checker.code`为512时即可获取flag
直接修改`Checker.code`为512即可
exp:
```js
function main(){
    Java.perform(function(){
        hookTest1();
    });
}
setImmediate(main);

function hookTest1(){
    var utils = Java.use("com.ad2001.frida0x3.Checker");
    utils.code.value = 512;
}
```
![[Pasted image 20251105193738.png]]