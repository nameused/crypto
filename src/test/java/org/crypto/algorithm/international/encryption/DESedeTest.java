package org.crypto.algorithm.international.encryption;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/9
 * @Company Dingxuan
 */
public class DESedeTest {
    DESede dESede;
    byte[] key;
    String testData = "testdata";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_ECB_PKCS5Padding = "DESede/ECB/PKCS5Padding";
    /**
     * ecb模式的c
     */
    private static final String CIPHER_ALGORITHM_ECB_ISO10126 = "DESede/ECB/ISO10126Padding";
    /**
     * cbc模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_PKCS5Padding = "DESede/CBC/PKCS5Padding";
    /**
     * cbc模式的ISO10126Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_ISO10126Padding = "DESede/CBC/ISO10126Padding";

    @Before
    public void setup() throws EncryptException {
        dESede = new DESede();
        key = dESede.genKey(168);
    }

    @Test
    public void ecbEncryptTest() throws EncryptException {
        System.out.println("---------------------DESede ECB PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = dESede.encrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = dESede.decrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }


    @Test
    public void cbcEncryptTest() throws EncryptException {
        System.out.println("---------------------DESede CBC PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥长度："+key.length);
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = dESede.encrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, testData.getBytes(), testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = dESede.decrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, testData.getBytes(), encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }
}