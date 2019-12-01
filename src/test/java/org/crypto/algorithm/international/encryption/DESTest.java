package org.crypto.algorithm.international.encryption;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.EncryptException;
import org.junit.Before;
import org.junit.Test;


import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/1
 * @Company Dingxuan
 */
public class DESTest {
    DES des;
    byte[] key;
    String testData = "test data";

    @Before
    public void setup() throws EncryptException {
        des = new DES();
        key = des.genKey(56);
    }

    @Test
    public void enprypt() throws EncryptException {
        System.out.println("test Data HexString is:"+Hex.toHexString(testData.getBytes()));
        System.out.println("des key is: " + Hex.toHexString(key));
        byte[] encryptData = des.enprypt(testData.getBytes(), testData.getBytes());
        System.out.println("encrypt Data: " + Hex.toHexString(encryptData));
        byte[] originalText=des.decrypt(testData.getBytes(),encryptData);
        System.out.println("originalText: "+Hex.toHexString(originalText));

    }

    @Test
    public void decrypt() {
    }
}