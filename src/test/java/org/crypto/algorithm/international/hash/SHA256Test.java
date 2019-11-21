package org.crypto.algorithm.international.hash;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

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
        System.out.println("signature length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}