![[Pasted image 20251105195928.png]]
和lab2的区别在于，这是个非静态的方法，需要找到已经实例化的`MainActivity`然后通过它调用`flag`方法，或者可以再实例化一个`MainActivity`，不过需要参数，这里用找的。
exp:
```js
function main(){
    Java.perform(function(){
        hook();
    });
}

function hook(){
    Java.choose("com.ad2001.frida0x5.MainActivity", {
        onMatch: function(instance){
            var flag = instance.flag(1337);
            console.log("Flag: " + flag);
        },
        onComplete: function(){}
    });

}
```
![[Pasted image 20251105201342.png]]