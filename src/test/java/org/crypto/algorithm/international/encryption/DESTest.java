package org.crypto.algorithm.international.encryption;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;


import static org.junit.Assert.*;

/**
 * DES算法测试类
 * JAVA6实现支持 56位秘钥
 * 分组模式支持 ECB、CBC、PCBC、CTR、
 * CFB8-CFB128、OFB、OFB8-OFB128
 * 填充方式支持 NOPadding、PKCS5Padding、ISO10126Padding
 * <p>
 * <p>
 * 而BC支持64位长度的秘钥
 * 分组模式同上
 * 填充方式支持 PKCS7Padding、ISO10126d2Padding、
 * X932Padding、ISO7816d4Padding、ZeroBytePadding
 *
 * @Author: zhangmingyang
 * @Date: 2019/12/1
 * @Company Dingxuan
 */
public class DESTest {
    DES des;
    byte[] key;
    String testData = "testdata";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_ECB_PKCS5Padding = "DES/ECB/PKCS5Padding";
    /**
     * ecb模式的c
     */
    private static final String CIPHER_ALGORITHM_ECB_ISO10126 = "DES/ECB/ISO10126Padding";
    /**
     * cbc模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_PKCS5Padding = "DES/CBC/PKCS5Padding";
    /**
     * cbc模式的ISO10126Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_ISO10126Padding = "DES/CBC/ISO10126Padding";

    @Before
    public void setup() throws EncryptException {
        des = new DES();
        //BC实现长度为64、java6实现长度为56
        key = des.genKey(56);
    }

    @Test
    public void ecbEncryptTest() throws EncryptException {
        System.out.println("---------------------DES ECB PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = des.encrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, testData.getBytes(), null, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = des.decrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, testData.getBytes(), null, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }


    @Test
    public void cbcEncryptTest() throws EncryptException {
        System.out.println("---------------------DES CBC PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = des.encrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = des.decrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }

}