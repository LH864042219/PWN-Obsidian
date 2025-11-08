![[Pasted image 20251105203904.png]]
![[Pasted image 20251105203918.png]]
和lab6的区别在于，这回的`Checker`创建了一个构造函数，`new`的时候要注意。
exp:
```js
function main(){
    Java.perform(function(){
        hook();
    });
}

function hook(){
    var utils = Java.use("com.ad2001.frida0x7.Checker");
    var checker = utils.$new(513, 513);
    console.log("Checker num1: " + checker.num1.value);
    console.log("Checker num2: " + checker.num2.value);
    Java.choose("com.ad2001.frida0x7.MainActivity", {
        onMatch: function(instance){
            instance.flag(checker);
        },
        onComplete: function(){}
    });

}
```
![[Pasted image 20251105203755.png]]
