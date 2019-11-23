# app协议逆向破解
```
思路：这种app逆向方式比较通用，能够解决大部分app协议加密破解。主要思路是利用frida hook java jdk 中的加密
函数与方法，打印响应参数分析
```
### 步骤
1. 启动脚步js_hook.js   (frida -U -l js_hook.js -f com.lang.testso --no-pause)
   * 脚步中包含了hook MD5 AES DES RSA 等一些列加密算法；以及解决app 无法抓包的ssl ping脚步
2. 启动app点击发送请求，查看响应日志
 