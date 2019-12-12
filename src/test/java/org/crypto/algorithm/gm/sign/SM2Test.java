package org.crypto.algorithm.gm.sign;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.crypto.common.exception.SignException;
import org.crypto.common.utils.GmUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.*;

import static org.crypto.common.utils.GmUtil.*;


/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class SM2Test {

    private static final String SIGNATURE_ALGORITHM = "SM3WithSM2";
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
        byte[] signature = sm2.sign(data.getBytes(), keyPair.getPrivate(), SIGNATURE_ALGORITHM);

        System.out.println("BC实现的签名值：" + Hex.toHexString(signature));
        System.out.println("签名长度：" + signature.length * 8);

        //BC　实现的签名值为rs的asn1格式，需要转换为r||s拼接的方式，才符合国密检测工具的验证
        byte[] encode = GmUtil.rsAsn1ToPlainByteArray(signature);
        System.out.println("符合国密标准的签名值:" + Hex.toHexString(encode));
        System.out.println("签名长度：" + encode.length * 8);

        //r||s的原文转换为asn1格式
        byte[] decode = GmUtil.rsPlainByteArrayToAsn1(encode);

        Assert.assertArrayEquals(signature, decode);

        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyPair.getPrivate();
        System.out.println("私钥长度：" + bcecPrivateKey.getD().toByteArray().length);
        System.out.println("私钥内容：" + Hex.toHexString(bcecPrivateKey.getD().toByteArray()));

        BCECPublicKey bcecPublicKey = (BCECPublicKey) keyPair.getPublic();
        System.out.println("公钥长度：" + bcecPublicKey.getQ().getEncoded(false).length);
        System.out.println("公钥内容：" + Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));

        boolean result = sm2.verify(data.getBytes(), keyPair.getPublic(), signature, SIGNATURE_ALGORITHM);
        System.out.println("verify result:" + result);
    }

    @Test
    public void encrypt() {
        String data = "this is test data";
        System.out.println("原文数据：" + Hex.toHexString(data.getBytes()));

        BCECPublicKey bcecPublicKey = (BCECPublicKey) keyPair.getPublic();
        System.out.println("公钥长度：" + bcecPublicKey.getQ().getEncoded(false).length);
        System.out.println("公钥内容：" + Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));

        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyPair.getPrivate();
        System.out.println("私钥长度：" + bcecPrivateKey.getD().toByteArray().length);
        System.out.println("私钥内容：" + Hex.toHexString(bcecPrivateKey.getD().toByteArray()));

        byte[] encryptData = sm2.sm2EncryptOld(data.getBytes(), keyPair.getPublic());
        System.out.println("公钥加密后的数据：" + Hex.toHexString(encryptData));
        byte[] originalText = sm2.sm2DecryptOld(encryptData, keyPair.getPrivate());
        System.out.println("解密后的数据：" + Hex.toHexString(originalText));
    }

    @Test
    public void encrypt1() throws IOException {
        String data = "this is test data 12";
        System.out.println("明文长度：" + data.getBytes().length);
        System.out.println("原文数据：" + Hex.toHexString(data.getBytes()));

        BCECPublicKey bcecPublicKey = (BCECPublicKey) keyPair.getPublic();
        System.out.println("公钥长度：" + bcecPublicKey.getQ().getEncoded(false).length);
        System.out.println("公钥内容：" + Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));

        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyPair.getPrivate();
        System.out.println("私钥长度：" + bcecPrivateKey.getD().toByteArray().length);
        System.out.println("私钥内容：" + Hex.toHexString(bcecPrivateKey.getD().toByteArray()));

        byte[] encryptData = sm2.sm2Encrypt(data.getBytes(), keyPair.getPublic());
        System.out.println("公钥加密后的数据：" + Hex.toHexString(encryptData));
        System.out.println("der编码后的加密数据："+Hex.toHexString(sm2.encodeSM2CipherToDER(encryptData)));

        byte[] originalText = sm2.sm2Decrypt(encryptData, keyPair.getPrivate());
        System.out.println("解密后的数据：" + Hex.toHexString(originalText));
    }


    @Test
    public void test() throws SignException, CryptoException {
        String content = "原文：7468697320697320746573742064617461\n" +
                "BC实现的签名值：304402201ca079a90590d1190d5b4381bf381a9d44140fe94cec825129ccd1b08dcbac5102202442c430b784633bfafe7547be1f4d94dd36de54edce7897f27142cfecf67c35\n" +
                "签名长度：560\n" +
                "符合国密标准的签名值:1ca079a90590d1190d5b4381bf381a9d44140fe94cec825129ccd1b08dcbac512442c430b784633bfafe7547be1f4d94dd36de54edce7897f27142cfecf67c35\n" +
                "签名长度：512\n" +
                "私钥长度：33\n" +
                "私钥内容：009ae9b635077a43aecc013723240ba316f7f74c78bd8958097b1dddadcd2f6c37\n" +
                "公钥长度：65\n" +
                "公钥内容：045646548c718c7ef2b70e57091425f487a0285433a57ae82eee9f58db840d4e4714e60e271875cf9e4b56cc2ce5e8490e50269637b2162086e56d46a29d3662b1\n" +
                "verify result:true";
        byte[] sk = Hex.decode("009ae9b635077a43aecc013723240ba316f7f74c78bd8958097b1dddadcd2f6c37");
        PrivateKey privateKey = byteArrayToPrivateKey(sk);
        String data = "this is test data";
        byte[] sign = sm2.sign(data.getBytes(), privateKey, SIGNATURE_ALGORITHM);
        System.out.println("sm2签名值:" + Hex.toHexString(sign));
        PublicKey publicKey = byteArrayToPublickey(Hex.decode("045646548c718c7ef2b70e57091425f487a0285433a57ae82eee9f58db840d4e4714e60e271875cf9e4b56cc2ce5e8490e50269637b2162086e56d46a29d3662b1"));
        boolean result = sm2.verify(data.getBytes(), publicKey,Hex.decode("304402201ca079a90590d1190d5b4381bf381a9d44140fe94cec825129ccd1b08dcbac5102202442c430b784633bfafe7547be1f4d94dd36de54edce7897f27142cfecf67c35"), SIGNATURE_ALGORITHM);
        System.out.println("验签结果：" + result);
    }

}