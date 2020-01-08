package org.crypto.algorithm.international.sign;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class DSATest {
    private static final String SIGNATURE_ALGORITHM = "SHA1WithDSA";
    DSA dsa;
    KeyPair keyPair;
    @Before
    public void setup() throws SignException {
        dsa=new DSA();
        keyPair=dsa.genKeyPair(1024);
    }

    @Test
    public void genKeyPair() {
        System.out.println("privateKey:" + Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() throws SignException {
        String data = "this is test data";
        byte[] signature = dsa.sign(data.getBytes(), keyPair.getPrivate(),SIGNATURE_ALGORITHM);
        System.out.println("签名值16进制值:"+ Hex.toHexString(signature));
        System.out.println("签名长度："+signature.length);
        boolean result = dsa.verify(data.getBytes(), keyPair.getPublic(), signature,SIGNATURE_ALGORITHM);
        System.out.println("verify result:" + result);
    }

    @Test
    public void verify() {
    }
}