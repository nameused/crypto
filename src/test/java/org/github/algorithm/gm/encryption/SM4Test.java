package org.github.algorithm.gm.encryption;

import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;

public class SM4Test {
    SM4 sm4;
    byte[] key;
    String testData = "testdata";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_ECB_PKCS5Padding = "SM4/ECB/PKCS5Padding";
    /**
     * ecb模式的PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM_CBC_PKCS5Padding = "SM4/CBC/PKCS7Padding";
    @Before
    public void setup() throws EncryptException {
        sm4=new SM4();
        key=sm4.genKey(128);
    }

    @Test
    public void genKey() {
    }

    @Test
    public void ecbEncrypt() throws EncryptException {
        System.out.println("---------------------SM4 ECB PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = sm4.encrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = sm4.decrypt(CIPHER_ALGORITHM_ECB_PKCS5Padding, key, null, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }

    @Test
    public void cbcEncrypt() throws EncryptException {
        System.out.println("---------------------SM4 CBC PKCS5Padding---------------------------");
        System.out.println("测试数据16进制字符串:" + Hex.toHexString(testData.getBytes()));
        System.out.println("密钥: " + Hex.toHexString(key));
        byte[] encryptData = sm4.encrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, testData.getBytes());
        System.out.println("加密后数据: " + Hex.toHexString(encryptData));
        byte[] originalText = sm4.decrypt(CIPHER_ALGORITHM_CBC_PKCS5Padding, key, key, encryptData);
        System.out.println("原始数据：" + Hex.toHexString(originalText));
    }
}