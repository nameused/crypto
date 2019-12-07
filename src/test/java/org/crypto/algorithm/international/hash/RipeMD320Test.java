package org.crypto.algorithm.international.hash;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/7
 * @Company Dingxuan
 */
public class RipeMD320Test {
    RipeMD320 ripeMD320;

    @Before
    public void setup() {
        ripeMD320 = new RipeMD320();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = ripeMD320.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}