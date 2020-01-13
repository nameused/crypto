package org.github.algorithm.international.hash;

import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SHA256Test {
    SHA256 sha256;

    @Before
    public void setup() {
        sha256 = new SHA256();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = sha256.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}