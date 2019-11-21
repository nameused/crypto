package org.crypto.algorithm.gm.hash;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

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
        String testData = "abc";
        byte[] hash = sm3.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("signature length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}