package org.github.algorithm.gm.sign;


import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.github.common.exception.SignException;
import org.github.common.utils.GmUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

import static org.github.common.utils.GmUtil.*;


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
        System.out.println("privateKey:" + Base64.toBase64String(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Base64.toBase64String(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void gmSignDataTest() throws SignException {
        //国密SM2算法的签名与验签都是预处理前
        System.out.println("========================基于国密检测工具SM2签名验证测试==========================");
        byte[] sk = Hex.decode("50E7324D208DC091C089FB98FAEC64468EAE6789B0F707EDFE86EF7CB754DAEA");
        //sm2签名时制定随机数种子，固定随机数
        BigInteger bigInteger = new BigInteger("105346645824813091583495808130328573841359553048162952770093773822631478486079");
        System.out.println("随机数16进制输出:" + Hex.toHexString(BigIntegertoByteArray(bigInteger)));
        PrivateKey privateKey = byteArrayToPrivateKey(sk);
        byte[] sign = sm2.sign(Hex.decode("B0448E89946BB21EC649FDF3BA46296602182849FBE2D329AAF843DE0D7CA73F"), privateKey, SIGNATURE_ALGORITHM);
        byte[] encode = GmUtil.rsAsn1ToPlainByteArray(sign);
        System.out.println("符合国密标准的签名值:" + Hex.toHexString(encode));
        PublicKey publicKey = byteArrayToPublickey(Hex.decode("046456CC2649C6216281EE91DCDC5A75C8E92706C3C9B85362796E8E8277BB34A663C11AF6619F6C5A452626EF2703BE187681A816D988467DED48D17E5E54F613"));
        boolean result = sm2.verify(Hex.decode("B0448E89946BB21EC649FDF3BA46296602182849FBE2D329AAF843DE0D7CA73F"), publicKey, sign, SIGNATURE_ALGORITHM);
        System.out.println("验证结果:" + result);
    }

    @Test
    public void gmEncryptDataTest() throws SignException, IOException {
        System.out.println("========================基于国密检测工具SM2数据加密验证测试=============开始=============");
        PublicKey publicKey = byteArrayToPublickey(Hex.decode("046456CC2649C6216281EE91DCDC5A75C8E92706C3C9B85362796E8E8277BB34A663C11AF6619F6C5A452626EF2703BE187681A816D988467DED48D17E5E54F613"));
        byte[] data = Hex.decode("B0448E89946BB21EC649FDF3BA46296602182849FBE2D329AAF843DE0D7CA73F");
        BigInteger bigInteger = new BigInteger("105346645824813091583495808130328573841359553048162952770093773822631478486079");
        PrivateKey privateKey = byteArrayToPrivateKey(Hex.decode("50E7324D208DC091C089FB98FAEC64468EAE6789B0F707EDFE86EF7CB754DAEA"));
        System.out.println("随机数16进制输出:" + Hex.toHexString(BigIntegertoByteArray(bigInteger)));
        byte[] encryptData = sm2.sm2EncryptOld(data, publicKey);
        System.out.println("按照C1||C2||C3的方式加密后的数据:" + Hex.toHexString(encryptData));
        System.out.println("Der编码后的加密数据：" + Hex.toHexString(SM2.encodeSM2CipherToDER(encryptData)));
        byte[] content = sm2.sm2DecryptOld(encryptData, privateKey);
        System.out.println(Hex.toHexString(content));
        System.out.println("按照C1||C3||C2的方式加密后的数据:" + Hex.toHexString(SM2.changeC1C2C3ToC1C3C2(encryptData)));
        System.out.println("原数据:"+Hex.toHexString(data));
        byte[] c1c3c2 = sm2.encrypt(data, publicKey);
        System.out.println("按照C1||C3||C2的方式加密后的数据:" + Hex.toHexString(c1c3c2));
        byte[] plainText= sm2.decrypt(c1c3c2, privateKey);
        System.out.println("解密后的数据:"+Hex.toHexString(plainText));
        System.out.println("========================基于国密检测工具SM2数据加密验证测试=============结束=============");
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

}