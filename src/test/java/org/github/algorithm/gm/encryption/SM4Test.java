package org.github.algorithm.gm.encryption;

import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;

import java.security.Security;

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
        sm4 = new SM4();
        //key=sm4.genKey(128);
        key = Base64.decode("C50In7xnnP4Daie9oPZ6uw==");
        System.out.println("密钥长度：" + key.length);
        System.out.println(Hex.toHexString(key));
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

    @Test
    public void decTest() throws EncryptException {
        String key = "490a7b36dafc5b6bf37783118bdfe116";
        String encData = "08c818717bf49c72305468aa95fc920ae9ba6ca1a47b1855c6641c289c06066a57fc901e6af087caa0d9f0a5b4a40d0fc5d1eedb5375b1c9503bbce0f2f1e510";
        System.out.println("密钥长度：" + Hex.decode(key).length);
        System.out.println("加密数据长度：" + Hex.decode(encData).length);
        byte[] data = sm4.decrypt("SM4/ECB/NoPadding", Hex.decode(key), null, Hex.decode(encData));
        System.out.println(Hex.toHexString(data));
        System.out.println(new String(data));
    }
}