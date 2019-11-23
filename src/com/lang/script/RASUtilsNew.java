package com.lang.script;

import javax.crypto.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/*******************************************************************************
 * AES加解密算法
 * http://tools.lami.la/jiami/aes
 * 说明：AES数据块长度为128位，所以IV长度需要为16个字符（ECB模式不用IV），密钥根据指定密钥位数分别为16、24、32个字符，IV与密钥超过长度则截取，不足则在末尾填充'\0'补足
 *******************************************************************************/


public class RASUtilsNew {

    public static void encrypt() {


        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128); // The AES key size in number of bits
            SecretKey secKey = generator.generateKey();

            String plainText = "Please encrypt me urgently...";
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
            byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();

            PublicKey puKey = keyPair.getPublic();
            PrivateKey prKey = keyPair.getPrivate();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PUBLIC_KEY, puKey);
            byte[] encryptedKey = cipher.doFinal(secKey.getEncoded()/*Seceret Key From Step 1*/);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }



    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
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
     * 公钥加密
     * @param encryptingStr
     * @param publicKeyStr
     * @return
     */
    public static String encryptByPublic(String encryptingStr, String publicKeyStr){
        try {
            // 将公钥由字符串转为UTF-8格式的字节数组
//            byte[] publicKeyBytes = decryptBase64(publicKeyStr);
            byte[] publicKeyBytes = hexStringToByteArray(publicKeyStr);
            // 获得公钥
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 取得待加密数据
            byte[] data = encryptingStr.getBytes("UTF-8");
            KeyFactory factory;
            factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据加密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 返回加密后由Base64编码的加密信息
            return encryptBase64(cipher.doFinal(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥解密
     * @param encryptedStr
     * @param publicKeyStr
     * @return
     */
    public static String decryptByPublic(String encryptedStr, String publicKeyStr){
        try {
            // 对公钥解密
            byte[] publicKeyBytes = decryptBase64(publicKeyStr);
            // 取得公钥
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 取得待加密数据
            byte[] data = decryptBase64(encryptedStr);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            // 返回UTF-8编码的解密信息
            return new String(cipher.doFinal(data), "UTF-8");
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
        String Key = "30819f300d06092a864886f70d010101050003818d0030818902818100d65b8500176d70d40b6986cb15c9e6b11835e44744582a176cc4f2cb5a91f792fa3245b69f280825eeba967bc69dd1ee962323daa9cc8493502042c4c2cf87d3ea798015213fd06ea266f2f2c04d467d02e757e6377d1754dfc4b2f8545f3c805131bf02b03373088ba63c5e39674d70886711557699fd472158ddda7bdb17f30203010001";
        // 需要加密的字串
        String Src = "17611597504";
        System.out.println(Src);
        // 加密
        String enString = RASUtilsNew.encryptByPublic(Src, Key);
        System.out.println("加密后的字串是：" + enString);




    }
}