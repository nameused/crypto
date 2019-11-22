package org.crypto.algorithm.gm.sign;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.SignException;
import org.crypto.common.utils.GmUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;


/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
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
        System.out.println("原文：" + Hex.toHexString(data.getBytes()));
        byte[] signature = sm2.sign(data.getBytes(), keyPair.getPrivate());

        System.out.println("BC实现的签名值：" + Hex.toHexString(signature));
        System.out.println("签名长度：" + signature.length * 8);

        //BC　实现的签名值为rs的asn1格式，需要转换为r||s拼接的方式，才符合国密检测工具的验证
        byte[] encode = GmUtil.rsAsn1ToPlainByteArray(signature);
        System.out.println("符合国密标准的签名值:" + Hex.toHexString(encode));
        System.out.println("签名长度：" + encode.length * 8);

        //r||s的原文转换为asn1格式
        byte[] decode=GmUtil.rsPlainByteArrayToAsn1(encode);

        Assert.assertArrayEquals(signature,decode);

        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyPair.getPrivate();
        System.out.println("私钥长度：" + bcecPrivateKey.getD().toByteArray().length);
        System.out.println("私钥内容：" + Hex.toHexString(bcecPrivateKey.getD().toByteArray()));

        BCECPublicKey bcecPublicKey = (BCECPublicKey) keyPair.getPublic();
        System.out.println("公钥长度：" + bcecPublicKey.getQ().getEncoded(false).length);
        System.out.println("公钥内容：" + Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));

        boolean result = sm2.verify(data.getBytes(), keyPair.getPublic(), signature);
        System.out.println("verify result:" + result);
    }
}