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
public class MD5Test {
    MD5 md5;

    @Before
    public void setup() {
        md5 = new MD5();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = md5.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:"+hash.length*8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}