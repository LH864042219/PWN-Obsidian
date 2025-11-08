调用到了一个`check_flag`函数
![[Pasted image 20251107203621.png]]
进ida中可以看看
![[Pasted image 20251107203655.png]]
可以看到恒返回1，所以需要劫持其返回1337。
exp:
```
function main(){
    Java.perform(function(){
        var utils = Java.use("com.ad2001.a0x9.MainActivity");
        utils.check_flag.implementation = function(input){
            return 1337;
        }
    });
}setImmediate(main);
```
![[Pasted image 20251107204102.png]]