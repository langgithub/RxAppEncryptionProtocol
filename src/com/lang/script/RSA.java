package com.lang.script;

import javax.crypto.Cipher;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/*******************************************************************************
 加解密：公钥加密，私钥解密
 签名验证：私钥签名，公钥验签
 *******************************************************************************/
public class RSA {
    public static final String RSA_ALGORITHM = "RSA";
    public static final Charset UTF8 = Charset.forName("UTF-8");

    public static void main(String [] args) throws Exception {
        // generate public and private keys
        KeyPair keyPair = buildKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        RSA.savePrivateKey(privateKey);
        RSA.savePublicKey(publicKey);

        // encrypt the message
        String encrypted=encrypt(privateKey, "This is a secret message");
        System.out.println(encrypted);  // <<encrypted message>>
        
        // decrypt the message
        System.out.println(decrypt(publicKey, encrypted));     // This is a secret message
    }

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static String encrypt(PrivateKey privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes(UTF8)));
    }
    
    public static String decrypt(PublicKey publicKey, String encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
    }

    /**
     * 从字符串中加载公钥
     *
     */
    public static RSAPublicKey loadPublicKey(String publicKeyStr) throws Exception {
        try {
            byte[] buffer = base64Decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static RSAPrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
        try {
            byte[] buffer = base64Decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static void savePublicKey(PublicKey publicKey) throws IOException {
        // 得到公钥字符串
        String publicKeyString = base64Encode(publicKey.getEncoded());
        System.out.println("publicKeyString="+publicKeyString);
        FileWriter fw = new FileWriter("publicKey.keystore");
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(publicKeyString);
        bw.close();
    }

    public static  void savePrivateKey(PrivateKey privateKey) throws IOException {
        // 得到私钥字符串
        String privateKeyString = base64Encode(privateKey.getEncoded());
        System.out.println("privateKeyString="+privateKeyString);

        BufferedWriter bw = new BufferedWriter(new FileWriter("privateKey.keystore"));
        bw.write(privateKeyString);
        bw.close();
    }

    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    public static byte[] base64Decode(String data) throws IOException {
        return Base64.getDecoder().decode(data);
    }
}