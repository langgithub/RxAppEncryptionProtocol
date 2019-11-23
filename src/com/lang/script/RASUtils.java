package com.lang.script;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/*******************************************************************************
 * frida调试逆向RSA
 *******************************************************************************/
public class RASUtils {


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
        System.out.println(new String(data));
        return data;
    }

    /**
     * BASE64 解码
     * @param key 需要Base64解码的字符串
     * @return 字节数组
     */
    public static byte[] decryptBase64(String key) {
        return Base64.getDecoder().decode(key);
    }

    /**
     * BASE64 编码
     * @param key 需要Base64编码的字节数组
     * @return 字符串
     */
    public static String encryptBase64(byte[] key) {
        return new String(Base64.getEncoder().encode(key));
    }

    /**
     * 确定对方用公钥加密
     * @param encryptingStr
     * @param publicKeyStr
     * @return
     */
    public static String encryptByPublic(String encryptingStr, String publicKeyStr){
        try {
            // 将公钥由字符串转为UTF-8格式的字节数组
            byte[] publicKeyBytes = hexStringToByteArray(publicKeyStr);
            // 获得公钥
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 取得待加密数据
            byte[] data = encryptingStr.getBytes("UTF-8");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            System.out.println(keyFactory.getAlgorithm());
            // 对数据加密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 返回加密后由Base64编码的加密信息
            return encryptBase64(cipher.doFinal(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 确定对方用私钥加密 or 解密
     * @param encryptingStr
     * @param privateKeyStr
     * @return
     */
    public static String encryptByPrivate(String encryptingStr, String privateKeyStr){
        try {
            // 将公钥由字符串转为UTF-8格式的字节数组
            byte[] publicKeyBytes = hexStringToByteArray(privateKeyStr);
            // 获得公钥
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicKeyBytes);
            // 取得待加密数据
            byte[] data = encryptingStr.getBytes("UTF-8");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            // 对数据加密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            // 返回加密后由Base64编码的加密信息
            return encryptBase64(cipher.doFinal(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 确定对方用公钥加密 or 解密
     * @param encryptedStr
     * @param publicKeyStr frida 打印出的key
     * @return
     */
    public static String decryptByPublic(String encryptedStr, String publicKeyStr){
        try {
            // 对公钥解密
            byte[] publicKeyBytes = hexStringToByteArray(publicKeyStr);
            // 取得公钥
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 取得待加密数据
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            // 返回UTF-8编码的解密信息
            return new String(cipher.doFinal(hexStringToByteArray(encryptedStr)));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) throws Exception {
        /*
         * 加密用的Key 可以用26个字母和数字组成，最好不要用保留字符，虽然不会错，至于怎么裁决，个人看情况而定
         * 此处使用AES-128-CBC加密模式，key需要为16位。
         */
        String Key = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100bbc9efcf4a734e3bb6427c25098f7c727a259ec84ed2ec495d9908307b8840dacea846eae57e869264f55a49dcd8eb34b44a92b483d75b1986b24eee7adc98d440ba1f5558c326b9fb5f7d2820d4d4a546c18c2b550fcd0d1c4c20c61e0fe84cb31e3e2393b7adbe266ccef4ab608414e922982f9ecf123e56ba78d87094348cb2a205abde105ccfce4db720a9ce6388076afc884abc53b0f16974cd8cd74d546dc9bea5e7793e7f66507edd366ef82adf32d65f8db1094728929c438c04b938d5cfe48d6cbcf097fb5fe1e4a31c0d11e6caf8c6b61dc6b514b4387403c212fec12be4286b08de38855528a475363d403c73248305bf6644f9c4a9a799406a4d0203010001";
        // 需要加密的字串
        String Src = "This is a secret message";
        System.out.println(Src);
        // 加密
//        String enString = RASUtils.encryptByPrivate(Src, Key);
//        System.out.println("加密后的字串是：" + enString);

        String encodeBody="79e7825c7dad8dc813118aff2c31122aaac9578a4c0c3bb5ce058d919fa5bd4256f9ea43a38b4e334c78e3bd993be05487d02a3261909d02bebd48a9c6691915b053e700478f33b48cf1a4613f5093daf0e2b897d60090cd8d399cb803eee1d86e5523db27c4cc619b3d170f8673d5cae507498b3a13cb05e1dbd79b23ba84b6255a71b7763042d69b401143b6906e9ecc79803d87e0cad0441d074a12f44acd65e6c0f66a8135d11994b8c45d9356f3e1bbecbdbd6b4852c65fe65f020a2f8b8a29d53f4d8cbe001992d30ac623bea9ee195a38cd0af381dbf8be51a4b5788df578f29f6ba881498dd491f3515ed7b762522fe9a0f7d216a4fdddf51e28d6ed";
        String eString = RASUtils.decryptByPublic(encodeBody, Key);
        System.out.println("解密后的字串是：" + eString);
    }
}