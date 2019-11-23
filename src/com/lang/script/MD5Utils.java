package com.lang.script;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*****************************************************************************************
 * MD5加密
 *****************************************************************************************/
public class MD5Utils {
    private static final char[] HEX_DIGITS = { 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102 };

    public static String getMD5String(String str) {
        byte[] paramArrayOfByte = str.getBytes();
        String result = null;

        try {
            //首先进行实例化和初始化
            MessageDigest md = MessageDigest.getInstance("MD5");
            //得到一个操作系统默认的字节编码格式的字节数组
            //对得到的字节数组进行处理
            md.update(paramArrayOfByte);
            //进行哈希计算并返回结果
            byte[] btResult = md.digest();
            result = bytesToHex(btResult,0, btResult.length);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;

    }

    public static String bytesToHex(byte[] bytedata, int starRatingStyle, int encyptBody) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = starRatingStyle; i < starRatingStyle + encyptBody; i++) {
            stringBuilder.append(byteToHex(bytedata[i]));
        }
        return stringBuilder.toString();
    }

    public static String byteToHex(byte paramByte)
    {
        return HEX_DIGITS[((paramByte & 0xF0) >> 4)] + "" + HEX_DIGITS[(paramByte & 0xF)];
    }



}