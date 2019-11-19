package org.crypto.sign.international;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/10
 * @Company Dingxuan
 */
public class ECDSATest {
    private ECDSA ecdsa;
    private KeyPair keyPair;
    @Before
    public void setup() throws SignException {
        ecdsa=new ECDSA();
        keyPair=ecdsa.genKeyPair(256);
    }

    @Test
    public void genKeyPair() {
        System.out.println("privateKey:" + Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() throws SignException {
        String data = "this is test data";
        byte[] signature = ecdsa.sign(data.getBytes(), keyPair.getPrivate());
        System.out.println("签名长度："+signature.length);
        boolean result = ecdsa.verify(data.getBytes(), keyPair.getPublic(), signature);
        System.out.println("verify result:" + result);
    }

    @Test
    public void verify() {
    }
}