package org.crypto.algorithm.international.hmac;

import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.HmacException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/7
 * @Company Dingxuan
 */
public class HmacMD5Test {
    HmacMD5 hmacMD5;
    byte[] key;
    @Before
    public void setup() throws HmacException {
        hmacMD5=new HmacMD5();
        key=hmacMD5.initKey();
    }

    @Test
    public void initKey() {
    }

    @Test
    public void hmac() throws HmacException { String testData = "test message";
        byte[] hash = hmacMD5.hmac(testData.getBytes(),key);
        Assert.assertNotNull(hash);
        System.out.println("digest length:" + hash.length * 8);
        System.out.println("test message‘s hash value:" + Hex.toHexString(hash));
    }
}