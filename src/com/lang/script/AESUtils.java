package com.lang.script;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;


/*******************************************************************************
 * Frida调试逆向AES
 *******************************************************************************/
public class AESUtils {

    /**
     * 16进制转byte[]
     * @param s
     * @return
     */
    public static byte[] hexStringToByteArray(String s) {

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        System.out.println("（key不一定可逆）hexStringToByteArray:"+new String(data));
        return data;
    }

    // 加密
    public static String Encrypt(String Src) throws Exception {
        String Key = "5565504004055655";
        byte[] key = Key.getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(hexStringToByteArray("a2f85a04b49048153c9e61f93be968f5"), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//"算法/模式/补码方式"

//        IvParameterSpec iv = new IvParameterSpec(hexStringToByteArray("0a010b05040f070917030106080c0d5b"));
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec,iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(Src.getBytes("UTF-8")));
    }


    // AES/CBC/PKCS5Padding 解密
    public static String Decrypt(String Src) throws Exception {
        try {
            String Key = "5565504004055655";
            byte[] key = Key.getBytes("ASCII");
            SecretKeySpec keySpec = new SecretKeySpec(hexStringToByteArray("a2f85a04b49048153c9e61f93be968f5"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//"算法/模式/补码方式"

//            IvParameterSpec iv = new IvParameterSpec(hexStringToByteArray("33626539303734623433363932616363"));
//            cipher.init(Cipher.DECRYPT_MODE, keySpec,iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(Src)));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    /**
     *
     * @param src
     * @return
     * @throws Exception
     */
    public static String HDecrypt(String src) throws Exception {
        System.out.println("HDecrypt");
        try {
            SecretKeySpec keySpec = new SecretKeySpec(hexStringToByteArray("d8ef94301cd8e477562d121342b0457b"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");//"算法/模式/补码方式"

            IvParameterSpec iv = new IvParameterSpec(hexStringToByteArray("37313865646437643239633038386234"));
            cipher.init(Cipher.DECRYPT_MODE, keySpec,iv);

            return new String(cipher.doFinal(hexStringToByteArray(src)));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }




    public static void main(String[] args) throws Exception {


        /*
         * 加密用的Key 可以用26个字母和数字组成，最好不要用保留字符，虽然不会错，至于怎么裁决，个人看情况而定
         * 此处使用AES-128-CBC加密模式，key需要为16位。
         */
        // 需要加密的字串
        String Src = "howtodoinjava.com";
        System.out.println(Src);
        // 加密
        String enString = AESUtils.Encrypt(Src);
        System.out.println("加密后的字串是：" + enString);


        // 解密
        String DeString = AESUtils.Decrypt(enString);
        System.out.println("解密后的字串是：" + DeString);

        // 逆向复制
        String result=AESUtils.HDecrypt("aef24dbb6e865e821e72a4d6709c717f530e6e5cfd84aba9826ae2685684f5178c7f5e89dad1fd6d59a34d8e052e200d78ba2ffe78b518076d1044082c3eec142c2f0a01e895ac960e8e7472f83052a90dce40bac02572cafa50169aa90c952667e682907de745b51fd84a995d57dfe3dc3f56d5e7a09fe4b58d80ab29c05e177b5edd87732fb4eeb49ed3715ad9b9becc9c769dfb1cf62d3b259666023cac0a60717bb806c8f9038ccda93a82d75924bc8a61e2b180680f2cca6bfdac3aa9b0c99b767e2f980c26f2ce86bb4cdd56fcb1598aefae38ed1f0e9d7c523d953aff784b56c365aae05731aa5a5da506c61da88ee1711f9663b4a3db0897e5a6e56d040321bd4ed4940c09f74fd387a96bb3410986adcab10bff69c5a1d37790ac6f");
        System.out.println("解密后的字串是：" + result);

    }
}