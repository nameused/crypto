package org.github.algorithm.international.hash;

import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.HashException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/7
 * @Company Dingxuan
 */
public class RipeMD256Test {
    RipeMD256 ripeMD256;

    @Before
    public void setup() {
        ripeMD256 = new RipeMD256();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = ripeMD256.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}