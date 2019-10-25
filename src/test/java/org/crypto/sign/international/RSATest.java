package org.crypto.sign.international;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.crypto.common.exception.SignException;
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

    @Test
    public void genKeyPair() throws SignException {
        RSA rsa = new RSA();
        KeyPair keyPair = rsa.genKeyPair(1024);
        System.out.println("privateKey:"+Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:"+Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() {

    }

    @Test
    public void verify() {
    }
}