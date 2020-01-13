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
public class HmacSHA224Test {

    HmacSHA224 hmacSHA224;
    byte[] key;
    @Before
    public void setup() throws HmacException {
        hmacSHA224=new HmacSHA224();
        key=hmacSHA224.initKey();
    }

    @Test
    public void initKey() {
    }

    @Test
    public void hmac() throws HmacException { String testData = "test message";
        byte[] hash = hmacSHA224.hmac(testData.getBytes(),key);
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}