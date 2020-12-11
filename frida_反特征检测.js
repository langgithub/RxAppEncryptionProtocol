// js hook jingdong  v9.3.0
// frida -U -l jingdong.js  -f com.jingdong.app.mall --no-pause

// frida 反检测  资料： https://bbs.pediy.com/thread-217482.htm
// 1. 改文件名称
// 2. 改端口
// 3. hook系统函数

//  改端口调用方式
//   ./flang  -l 0.0.0.0:12345
//  frida -H 127.0.0.1:12345  -l jingdong.js  -f com.jingdong.app.mall
//  %resume 启动

Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        console.log("fopen Interceptor attached onEnter...");
        console.log("fopen param0>>>>>>>" +  args[0].readCString());
    },
    onLeave: function(args) {
        console.log("fopen Interceptor attached onLeave...");
    }
})

var is_find_frida = false
Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter: function(args) {
//        console.log("strstr Interceptor attached onEnter...");
        console.log("strstr param0>>>>>>>" +  args[0].readCString());
        console.log("strstr param1>>>>>>>" +  args[1].readCString());
        if (args[1].readCString().indexOf("frida")){
            is_find_frida = true
        }else{
            is_find_frida = false
        }
    },
    onLeave: function(retval) {
        console.log("strstr Interceptor attached onLeave..." + retval);
        if (is_find_frida){
            retval.replace(ptr("0x0"))
        }
    }
})