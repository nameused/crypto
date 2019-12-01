package org.crypto.algorithm.international.sign;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;


/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class RSATest {
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    KeyPair keyPair;
    RSA rsa;

    @Before
    public void setup() throws SignException {
        rsa = new RSA();
        keyPair = rsa.genKeyPair(1024);
    }

    @Test
    public void genKeyPair() {
        System.out.println("privateKey:\n" + Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:\n" + Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() throws SignException {
        String data = "this is test data";
        byte[] signature = rsa.sign(data.getBytes(), keyPair.getPrivate(),SIGNATURE_ALGORITHM);
        System.out.println("签名长度："+signature.length*8);
        System.out.println("签名值：\n"+Base64.encode(signature));
        boolean result = rsa.verify(data.getBytes(), keyPair.getPublic(), signature,SIGNATURE_ALGORITHM);
        System.out.println("verify result:" + result);

    }
}