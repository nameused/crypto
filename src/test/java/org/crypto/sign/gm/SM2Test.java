package org.crypto.sign.gm;


import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;

/**
 * @Author: zhangmingyang
 * @Date: 2019/10/25
 * @Company Dingxuan
 */
public class SM2Test {
    private SM2 sm2;
    KeyPair keyPair;
    @Before
    public void setup() throws SignException {
        sm2=new SM2();
        keyPair=sm2.genKeyPair(0);
    }

    @Test
    public void genKeyPair() {
        System.out.println("privateKey:" + Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() throws SignException {
        String data="this is test data";
        byte[] signature=sm2.sign(data.getBytes(),keyPair.getPrivate().getEncoded());

//        Security.addProvider(new BouncyCastleProvider());
//        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) kp.getPrivate();
//        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) kp.getPublic();
//        BigInteger privateKey = ecpriv.getD();
//        ECPoint publicKey = ecpub.getQ();
//        System.out.println("publicKey size:"+publicKey.getEncoded(false).length);
//        System.out.println("privateKey size:"+privateKey.toByteArray().length);
        boolean result=sm2.verify(data.getBytes(),keyPair.getPublic().getEncoded(),signature);
        System.out.println("verify result:"+result);
    }

}