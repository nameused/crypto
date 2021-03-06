package org.crypto.sign.international;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.util.BitSet;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/10/25
 * @Company Dingxuan
 */
public class RSATest {
    KeyPair keyPair;
    RSA rsa;

    @Before
    public void setup() throws SignException {
        rsa = new RSA();
        keyPair = rsa.genKeyPair(1024);
    }

    @Test
    public void genKeyPair() {
        System.out.println("privateKey:" + Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() throws SignException {
        String data = "this is test data";
        byte[] signature = rsa.sign(data.getBytes(), keyPair.getPrivate().getEncoded());
        System.out.println(Hex.toHexString(signature).length());
        boolean result = rsa.verify(data.getBytes(), keyPair.getPublic().getEncoded(), signature);
        System.out.println("verify result:" + result);

    }
}