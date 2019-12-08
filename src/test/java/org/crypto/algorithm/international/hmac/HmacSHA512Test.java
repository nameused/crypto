package org.crypto.algorithm.international.hmac;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.HmacException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/8
 * @Company Dingxuan
 */
public class HmacSHA512Test {
    HmacSHA512 hmacSHA512;
    byte[] key;
    @Before
    public void setup() throws HmacException {
        hmacSHA512=new HmacSHA512();
        key=hmacSHA512.initKey();
    }

    @Test
    public void initKey() {
    }

    @Test
    public void hmac() throws HmacException { String testData = "test message";
        byte[] hash = hmacSHA512.hmac(testData.getBytes(),key);
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}