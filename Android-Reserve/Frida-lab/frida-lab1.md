首先打开apk
![[Pasted image 20251105185552.png]]
就只有输入一个数字，接着用jadx查看代码
1.5.3看不了check方法的代码，老版本还更好用说是
![[Pasted image 20251105185934.png]]
![[Pasted image 20251105185953.png]]
可以发现只有三个方法，当输入的数x和生成的随机数y，符合 `(y * 2) + 4 == x`时会启动自解密输出flag，~~当然也可以根据密文自己解~~。
方法很多，这里直接劫持`get_random`函数让其返回固定值，然后就可以获取flag
exp:
```js
function main(){
    Java.perform(function(){
        hookTest1();
    });
}
setImmediate(main);

function hookTest1(){
    var utils = Java.use("com.ad2001.frida0x1.MainActivity")
    utils.get_random.implementation = function() {
        return 0
    }
}
```
![[Pasted image 20251105191321.png]]