package org.crypto.algorithm.international.hash;

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
public class SHA512Test {
    SHA512 sha512;

    @Before
    public void setup() {
        sha512 = new SHA512();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = sha512.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("signature length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}