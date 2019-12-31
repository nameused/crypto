package org.crypto.algorithm.international.encryption;

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
public class IDEATest {
    IDEA idea;
    byte[] key;
    String testData = "testdatatestdatatestdatatestdata";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_ECB_PKCS5Padding = "IDEA/ECB/PKCS5Padding";
    /**
     * ecb模式的c
     */
    private static final String CIPHER_ALGORITHM_ECB_ISO10126 = "IDEA/ECB/ISO10126Padding";
    /**
     * cbc模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_PKCS5Padding = "IDEA/CBC/PKCS5Padding";
    /**
     * cbc模式的ISO10126Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_ISO10126Padding = "IDEA/CBC/ISO10126Padding";

    @Before
    public void setup() throws EncryptException {
        idea = new IDEA();
        key = idea.genKey(128);
    }

    @Test
    public void ecbEncryptTest() throws EncryptException {
        System.out.println("---------------------IDEA ECB PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = idea.encrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = idea.decrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }


    @Test
    public void cbcEncryptTest() throws EncryptException {
        System.out.println("---------------------IDEA CBC PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = idea.encrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = idea.decrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }
}