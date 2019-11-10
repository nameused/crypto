package org.crypto.sign.international;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;


/**
 * @Author: zhangmingyang
 * @Date: 2019/11/6
 * @Company Dingxuan
 */
public class DSATest {
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
    public void sign() {
    }

    @Test
    public void verify() {
    }
}