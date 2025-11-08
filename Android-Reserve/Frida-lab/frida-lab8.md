![[Pasted image 20251107202733.png]]
这里有一个从`.so`中读取的`strcmp`函数，`ida`中可以看到这个函数
![[Pasted image 20251107202911.png]]
可以看到里面在调用strcmp函数时会用到我们输入的参数和flag，我们可以抓取strcmp函数然后读取他的参数即可获取flag。
exp:
```js
function main(){
    Java.perform(function(){
        var strcmp_addr = Module.findExportByName("libc.so", "strcmp");
        console.log("strcmp address: " + strcmp_addr);
        Interceptor.attach(strcmp_addr, {
            onEnter: function(args){
                this.arg1 = args[0].readUtf8String();
                this.arg2 = args[1].readUtf8String();
                if(this.arg1 == "1234") {
                    console.log(this.arg1 + " matched!");
                    console.log(this.arg2);
                }
            },
            onLeave: function(retval){
            }
        });
    });
}setImmediate(main);
```
![[Pasted image 20251107203211.png]]