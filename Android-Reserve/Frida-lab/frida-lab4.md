`MainActivity`里没什么东西，直接看`Check`函数
![[Pasted image 20251105194133.png]]
当`get_flag`方法的参数为1337时即可获取flag。
exp:
```js
function main(){
    Java.perform(function(){
        hook();
    });
}

function hook(){
    var utils = Java.use("com.ad2001.frida0x4.Check");
    var inst = utils.$new();
    var flag = inst.get_flag(1337);
    console.log("Flag: " + flag);
}
```
与lab2不同的是，这里的Check尚未实例化，所以需要手动实例化后得到返回值
![[Pasted image 20251105195421.png]]