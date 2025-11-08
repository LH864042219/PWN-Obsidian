![[Pasted image 20251105202329.png]]
很简单，看代码后可以发现调用非静态方法`get_flag`并传入`Checker`类型的参数后即可获取flag，那么只要`new`一个`Checker`类型然后传入`get_flag`方法即可。
exp:
```js
function main(){
    Java.perform(function(){
        hook();
    });
}

function hook(){
    var utils = Java.use("com.ad2001.frida0x6.Checker");
    var checker = utils.$new();
    checker.num1.value = 1234;
    checker.num2.value = 4321;
    Java.choose("com.ad2001.frida0x6.MainActivity", {
        onMatch: function(instance){
            instance.get_flag(checker);
        },
        onComplete: function(){}
    });

}
```
![[Pasted image 20251105202251.png]]