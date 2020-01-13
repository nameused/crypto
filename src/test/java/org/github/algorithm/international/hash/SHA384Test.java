package org.github.algorithm.international.hash;

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
public class SHA384Test {
    SHA384 sha384;

    @Before
    public void setup() {
        sha384 = new SHA384();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = sha384.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}