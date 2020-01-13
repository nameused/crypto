package org.github.algorithm.international.encryption;

import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/29
 * @Company Dingxuan
 */
public class AESTest {
    AES aes;
    byte[] key;
    String testData = "testdatatestdatatestdatatestdata";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_ECB_PKCS5Padding = "AES/ECB/PKCS5Padding";
    /**
     * ecb模式的c
     */
    private static final String CIPHER_ALGORITHM_ECB_ISO10126 = "AES/ECB/ISO10126Padding";
    /**
     * cbc模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding";
    /**
     * cbc模式的ISO10126Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_ISO10126Padding = "AES/CBC/ISO10126Padding";

    @Before
    public void setup() throws EncryptException {
        aes = new AES();
        //BC实现长度为64、java6实现长度为56
        key = aes.genKey(256);
    }

    @Test
    public void ecbEncryptTest() throws EncryptException {
        System.out.println("---------------------AES ECB PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        System.out.println(testData.length());
        byte[] encryptData = aes.encrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = aes.decrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }


    @Test
    public void cbcEncryptTest() throws EncryptException {
        System.out.println("---------------------AES CBC PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = aes.encrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = aes.decrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }
}