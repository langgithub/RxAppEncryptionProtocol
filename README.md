# app协议逆向破解
```
思路：这种app逆向方式比较通用，能够解决大部分app协议加密破解。主要思路是利用frida hook java jdk 中的加密
函数与方法，打印响应参数分析
```
### 逆向步骤
1. 启动脚步js_hook.js   (frida -U -l js_hook.js -f com.lang.testso --no-pause)
   * 脚步中包含了hook MD5 AES DES RSA 等一些列加密算法；以及解决app 无法抓包的ssl ping脚步
2. 启动app点击发送请求，查看响应日志
   * AES
   ![AES](https://github.com/langgithub/RxAppEncryptionProtocol/blob/master/Rx_AES%E5%8A%A0%E5%AF%86%E6%97%A5%E5%BF%97.png)
   * RSA
   ![RSA](https://github.com/langgithub/RxAppEncryptionProtocol/blob/master/Rx_RSA%E5%8A%A0%E5%AF%86%E6%97%A5%E5%BF%97.png)
   
3. 还原算法，测试代码在com.lang.script下，将打印的16进制转换为byte字节数组，还原加密现场
4. frida工作中使用总结 https://langgithub.github.io/2019/08/01/frida%E4%BD%BF%E7%94%A8%E6%80%BB%E7%BB%93/