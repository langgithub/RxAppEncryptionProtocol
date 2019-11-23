// start with:
// frida -U -l pinning.js -f [APP_ID] --no-pause

console.log("Script loaded successfully 55");
// Uint8Array 代表答应字符串
// ByteArray2Hex 代表转换成16进制


//**************************************************************************************************//
//*****************************************MD5加密***************************************************//
//**************************************************************************************************//


// MD5
Java.perform(function(){
   var MessageDigest= Java.use('java.security.MessageDigest');

   MessageDigest.getInstance.overload('java.lang.String').implementation=function(arg1){
//        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
       console.log(arg1);
       var ret = this.getInstance(arg1);
       return ret;
   }

   MessageDigest.update.overload('[B').implementation=function(arg1){
       console.log("use update.overload('[B') ");
       parseIn(arg1);
       var ret = this.update(arg1);
       return ret;
   }

    MessageDigest.digest.overload().implementation=function(){
       console.log('use digest.overload()');
       var ret = this.digest();
       parseOut(ret);
       return ret;
   }

    MessageDigest.digest.overload("[B","int","int").implementation=function(buf,offset,len){
       console.log('use digest.overload("[B","int","int")');
       parseIn(buf);
       var ret = this.digest(buf,offset,len);
       parseOut(ret);
       return ret;
   }

   MessageDigest.digest.overload("[B").implementation=function(buf){
       console.log('use digest.overload("[B")');
       parseIn(buf);
       var ret = this.digest(buf);
       parseOut(ret);
       return ret;
   }
});



function parseIn(input){
    var Integer= Java.use('java.lang.Integer');
    var String= Java.use('java.lang.String');
    try{
        console.log("original:"+String.$new(input));
    }
    catch(e){
        console.log(parseHex(input));
    }
}

function parseOut(ret){
    var Integer= Java.use('java.lang.Integer');
    var String= Java.use('java.lang.String');
    var result = "";
    for(var i = 0;i<ret.length;i++){
        var val = ret[i];
        if(val < 0){
            val += 256;
        }
        var str = Integer.toHexString(val);
        if(String.$new(str).length()==1){
            str = "0" + str;
        }
        result += str;
    }
    console.log( "(32):" + result);
    console.log( "(32):" + result.toUpperCase());
    console.log( "(16):" + result.substring(8,24));
    console.log( "(16):" + result.substring(8,24).toUpperCase());
    console.log("");

}

function parseHex(input){
    var Integer= Java.use('java.lang.Integer');
    var byte_array = "";
    for(var j = 0;j<input.length;j++){
        var hex = Integer.toHexString(input[j]);
        if(hex.length == 1){
            hex = "0" + hex;
        }
        byte_array += hex;
    }

    console.log("original(hex):");
    var pair = "";
    var hex_table = "";
    for(var k = 0;k<byte_array.length;k++){
        pair += byte_array.charAt(k);
        if((k+1)%2 == 0){
            pair += " "
            hex_table += pair;
            pair = ""
        }

        if((k+1)%32 == 0){
            hex_table += "\n"
        }
    }
    return hex_table;

}


//**************************************************************************************************//
//*****************************************对称与非对称加密********************************************//
//**************************************************************************************************//

//AES or RSA
Java.perform(function x() {
    var secret_key_spec = Java.use("javax.crypto.spec.SecretKeySpec");
    secret_key_spec.$init.overload("[B", "java.lang.String").implementation = function (x, y) {
//        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send('{"my_type" : "KEY"}', new Uint8Array(x));
        send("KEY(注意：散列表生成的key不可逆): "+ByteArray2Hex(x));
        send('METHOD:' + y);
        return this.$init(x, y);
    }

    var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
    iv_parameter_spec.$init.overload("[B").implementation = function (x) {
        send('{"my_type" : "IV"}', new Uint8Array(x));
        send("IV: "+ByteArray2Hex(x));
        return this.$init(x);
    }


    var cipher = Java.use("javax.crypto.Cipher");
    // 确定加密方式 比如：AES(DES) or RSA
    cipher.getInstance.overload('java.lang.String').implementation = function (x) {
        send("METHOD: "+ x);
        return this.getInstance(x);
    }


    //RSA AES DES
    cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (x, y, z) {
        //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        if (x == 1) // 1 means Cipher.MODE_ENCRYPT
            send('{"my_type" : "hashcode_enc", "hashcode" :"' + this.hashCode().toString() + '" }');
        else // In this android app it is either 1 (Cipher.MODE_ENCRYPT) or 2 (Cipher.MODE_DECRYPT)
            send('{"my_type" : "hashcode_dec", "hashcode" :"' + this.hashCode().toString() + '" }');
        //We will have two lists in the python code, which keep track of the Cipher objects and their modes.


        //Also we can obtain the key,iv from the args passed to init call
        send('{"my_type" : "Key from call to cipher init"}', new Uint8Array(y.getEncoded()));
        send(ByteArray2Hex(y.getEncoded()));
        //arg z is of type AlgorithmParameterSpec, we need to cast it to IvParameterSpec first to be able to call getIV function
        send('{"my_type" : "IV from call to cipher init"}', new Uint8Array(Java.cast(z, iv_parameter_spec).getIV()));
        send(ByteArray2Hex(Java.cast(z, iv_parameter_spec).getIV()));
        //init must be called this way to work properly
        return cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").call(this, x, y, z);
    }

    // 重载
    cipher.init.overload('int', 'java.security.Key').implementation = function (x, y) {
        if (x == 1) // 1 means Cipher.MODE_ENCRYPT
            send('{"my_type" : "hashcode_enc", "hashcode" :"' + this.hashCode().toString() + '" }');
        else // In this android app it is either 1 (Cipher.MODE_ENCRYPT) or 2 (Cipher.MODE_DECRYPT)
            send('{"my_type" : "hashcode_dec", "hashcode" :"' + this.hashCode().toString() + '" }');
        //We will have two lists in the python code, which keep track of the Cipher objects and their modes.


        send('{"my_type" : "Key from call to cipher init"}', new Uint8Array(y.getEncoded()));
        send(ByteArray2Hex(y.getEncoded()));
        return this.init(x, y);
    }

    //  doFinal（加密，解密都会调用） 多种情况
    cipher.doFinal.overload("[B").implementation = function (x) {
        // 加密阶段 x 为明文
        send('{"my_type" : "before_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(x));
        send("before_doFinal >>>>>>>>>>>>>>> "+ByteArray2Hex(x));
        var ret = cipher.doFinal.overload("[B").call(this, x);
        // 解密阶段 new String(ret) 为明文
        send('{"my_type" : "after_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(ret));
        send("after_doFinal <<<<<<<<<<<<<<<< "+ByteArray2Hex(ret));
        return ret;
    }

    //
    var mac = Java.use("javax.crypto.Mac");
    mac.doFinal.overload("[B").implementation = function (x) {
        send('{"my_type" : "before_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(x));
        var ret = mac.doFinal.overload("[B").call(this, x);
        var hexstr = ByteArray2Hex(ret);
        send("after_doFinal HEX: " + hexstr);
        send("after_doFinal HEX: " + hexstr.toUpperCase());
        return ret;
    }

});

function Uint8ArrayToString(fileData){
    var dataString = "";
    for (var i = 0; i < fileData.length; i++) {
        dataString += String.fromCharCode(fileData[i]);
    }

    return dataString
}


function ByteArray2Hex(ret){
    var hexstr="";
    for (var i=0;i<ret.length;i++)
    {
        var b=(ret[i]>>>0)&0xff;
        var n=b.toString(16);
        hexstr += ("00" + n).slice(-2)+"";
    }
    return hexstr;
}


//**************************************************************************************************//
//*****************************************ssl ping抓包*********************************************//
//**************************************************************************************************//


// hook ssl pinning
Java.perform(function () {
    console.log('')
    console.log('===')
    console.log('* Injecting hooks into common certificate pinning methods *')
    console.log('===')

    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // build fake trust manager
    var TrustManager = Java.registerClass({
        name: 'com.sensepost.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {
            },
            checkServerTrusted: function (chain, authType) {
            },
            getAcceptedIssuers: function () {
                return [];
            }
        }
    });

    // pass our own custom trust manager through when requested
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    );
    SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
        console.log('! Intercepted trustmanager request');
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };

    console.log('* Setup custom trust manager');

    // okhttp3
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
            console.log('! Intercepted okhttp3: ' + str);
            return;
        };

        console.log('* Setup okhttp3 pinning')
    } catch(err) {
        console.log('* Unable to hook into okhttp3 pinner')
    }

    // trustkit
    try {
        var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
            console.log('! Intercepted trustkit{1}: ' + str);
            return true;
        };

        Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
            console.log('! Intercepted trustkit{2}: ' + str);
            return true;
        };

        console.log('* Setup trustkit pinning')
    } catch(err) {
        console.log('* Unable to hook into trustkit pinner')
    }

    // TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('! Intercepted TrustManagerImp: ' + host);
            return untrustedChain;
        }

        console.log('* Setup TrustManagerImpl pinning')
    } catch (err) {
        console.log('* Unable to hook into TrustManagerImpl')
    }

    // Appcelerator
    try {
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function () {
            console.log('! Intercepted Appcelerator');
        }

        console.log('* Setup Appcelerator pinning')
    } catch (err) {
        console.log('* Unable to hook into Appcelerator pinning')
    }
});