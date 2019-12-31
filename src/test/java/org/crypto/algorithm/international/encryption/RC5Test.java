package org.crypto.algorithm.international.encryption;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author zhangmingyang
 * @Date: 2019/12/31
 * @company Dingxuan
 */
public class RC5Test {
    RC5 rc5;
    byte[] key;
    String testData = "testdatatestdata";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_ECB_PKCS5Padding = "RC5/ECB/PKCS5Padding";
    /**
     * ecb模式的c
     */
    private static final String CIPHER_ALGORITHM_ECB_ISO10126 = "RC5/ECB/ISO10126Padding";
    /**
     * cbc模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_PKCS5Padding = "RC5/CBC/PKCS5Padding";
    /**
     * cbc模式的ISO10126Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_ISO10126Padding = "RC5/CBC/ISO10126Padding";

    @Before
    public void setup() throws EncryptException {
        rc5 = new RC5();
        key = rc5.genKey(128);
    }

    @Test
    public void ecbEncryptTest() throws EncryptException {
        System.out.println("---------------------RC5 ECB PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("测试数据长度:"+testData.getBytes().length);
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = rc5.encrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, testData.getBytes(), null, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = rc5.decrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, testData.getBytes(), null, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }


    @Test
    public void cbcEncryptTest() throws EncryptException {
        System.out.println("---------------------RC5 CBC PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = rc5.encrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = rc5.decrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }
}