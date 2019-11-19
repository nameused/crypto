package org.crypto.sign.gm;


import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.SignException;
import org.junit.Before;
import org.junit.Test;
import java.security.*;

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
        sm2 = new SM2();
        keyPair = sm2.genKeyPair(0);
    }

    @Test
    public void genKeyPair() {
        System.out.println("privateKey:" + Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Base64.encode(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void sign() throws SignException {

        String data = "this is test data";
        byte[] signature = sm2.sign(data.getBytes(), keyPair.getPrivate());

        System.out.println("签名长度："+signature.length);
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyPair.getPrivate();
        System.out.println("私钥长度："+bcecPrivateKey.getD().toByteArray().length);
        System.out.println("私钥内容："+ Hex.toHexString(bcecPrivateKey.getD().toByteArray()));


        BCECPublicKey bcecPublicKey = (BCECPublicKey) keyPair.getPublic();
        System.out.println("公钥长度："+bcecPublicKey.getQ().getEncoded(false).length);
        System.out.println("公钥内容："+Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));

        boolean result = sm2.verify(data.getBytes(), keyPair.getPublic(), signature);
        System.out.println("verify result:" + result);
    }

}