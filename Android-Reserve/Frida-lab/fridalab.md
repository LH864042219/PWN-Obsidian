上来先是一个绕过账号密码的验证
![[Pasted image 20251108140720.png]]
可以看到验证方法在`checkLogin`类中
![[Pasted image 20251108140805.png]]
直接hook这个方法使其恒返回true即可；
exp:
```js
function hook1(){
    Java.perform(function(){
        var utils = Java.use("com.lab.fridalab.MainActivity$checkLogin");
        utils.check.implementation = function(input1, input2){
            return true;
        }
    });
}
```
第二关需要修改VIP和cnt

可以看到一个是静态一个非静态，分别修改即可
![[Pasted image 20251108140948.png]]
exp:
```js
function hook2(){
    Java.perform(function(){
        var chall1 = Java.use("com.lab.fridalab.ChallActivity1");
        var clas1 = chall1.class;
        var fStatic = clas1.getDeclaredField("isVIP");
        fStatic.setAccessible(true);
        fStatic.setBoolean(null, true);
        Java.choose("com.lab.fridalab.ChallActivity1", {
            onMatch: function(instance){
                var cls = instance.class;
                var f = cls.getDeclaredField("cnt");
                f.setAccessible(true);
                f.setInt(instance, 999);
                console.log("cnt field set to 999 for instance: " + instance);
            },
            onComplete: function(){}
        });
    });
}
function hook2_1(){
    Java.perform(function(){
        var chall1 = Java.use("com.lab.fridalab.ChallActivity1");
        chall1.isVIP.value = true;
        Java.choose("com.lab.fridalab.ChallActivity1", {
            onMatch: function(instance){
                instance.cnt.value = 999;
            },
            onComplete: function(){}
        });
    });
}
```
两种方法都可以，第一种复杂点，第二种简单易懂。
第三种说明了要主动调用函数
![[Pasted image 20251108141117.png]]
那么先调用`getSecret`方法获取`secret`然后再用`mySetText`方法修改即可
![[Pasted image 20251108141127.png]]
exp:
```js
function hook3(){
    Java.perform(function(){
        Java.choose("com.lab.fridalab.ChallActivity2", {
            onMatch: function(instance){
                var secret = instance.getSecret();
                console.log("Secret from ChallActivity2: " + secret);
                instance.mySetText(secret);
            },
            onComplete: function(){}
        }); 
    });
}
```
第四关考dex
![[Pasted image 20251108141313.png]]
代码逻辑为先加载了`eee`文件里的内容并解密然后复制到`aaa`中，然后调用其中的`extCheck`方法，用dexdump直接脱可以直接得到
![[Pasted image 20251108141405.png]]
![[Pasted image 20251108141326.png]]
![[Pasted image 20251108141532.png]]
然后直接`hook` `extCheck`方法返回`tru`e即可
exp:
```js
function hook4(){
    Java.perform(function(){
        Java.enumerateClassLoaders({
            onMatch: function(loader){
                try{
                    if (loader.findClass("com.lab.frida.eCheck")){
                        console.log("Found class loader: " + loader);
                        Java.classFactory.loader = loader;
                    }
                } catch (e) {}
            }, onComplete: function(){}
        });
        Java.choose("com.lab.frida.eCheck", {
            onMatch: function(instance){
                instance.extCheck.implementation = function(){
                    return true;
                };
            },
            onComplete: function(){}
        });
    });
}
```
![[Pasted image 20251108141747.png]]