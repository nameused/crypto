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
public class RipeMD160Test {
    RipeMD160 ripeMD160;

    @Before
    public void setup() {
        ripeMD160 = new RipeMD160();
    }

    @Test
    public void hash() throws HashException {
        String testData = "test message";
        byte[] hash = ripeMD160.hash(testData.getBytes());
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}