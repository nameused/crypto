package org.github.algorithm.international.hmac;

import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.HmacException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/8
 * @Company Dingxuan
 */
public class HmacMD4Test {

    HmacMD4 hmacMD4;
    byte[] key;
    @Before
    public void setup() throws HmacException {
        hmacMD4=new HmacMD4();
        key=hmacMD4.initKey();
    }

    @Test
    public void initKey() {
    }

    @Test
    public void hmac() throws HmacException { String testData = "test message";
        byte[] hash = hmacMD4.hmac(testData.getBytes(),key);
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}