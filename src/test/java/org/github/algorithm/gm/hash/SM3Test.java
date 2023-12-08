package org.github.algorithm.gm.hash;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author zhangmingyang
 * @Date: 11/21/19
 * @Version 1.0.0
 */
public class SM3Test {
    SM3 sm3;

    @Before
    public void setup() {
        sm3 = new SM3();
    }

    @Test
    public void hash() throws HashException {
        String testData = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        byte[] data = Hex.decode("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        byte[] hash = sm3.hash(data);
        Assert.assertNotNull(hash);
        System.out.println("signature length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }

    @Test
    public void hashTest() throws HashException {
        String base64 = "MTIzNDU2NzgxMjM0NTY3OHF3ZXI=";
        byte[] hash = sm3.hash(Base64.decode(base64));
        System.out.println("计算哈希值Base64格式:" + Base64.toBase64String(hash));
    }
}