package org.github.algorithm.international.hash;

import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SHA1Test {
    SHA1 sha1;

    @Before
    public void setup() {
        sha1 = new SHA1();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = sha1.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}