package org.github.algorithm.gm.sign;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.github.algorithm.gm.encryption.SM4;
import org.github.algorithm.gm.hash.SM3;
import org.github.common.exception.EncryptException;
import org.github.common.exception.HashException;
import org.github.common.exception.SignException;
import org.github.common.utils.GmUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

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

        System.out.println(Hex.toHexString(keyPair.getPrivate().getEncoded()));
        System.out.println(Hex.toHexString(keyPair.getPublic().getEncoded()));
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
        System.out.println("sk------" + Hex.toHexString(privateKey.getEncoded()));
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
        sm2.genKeyPair(0).getPublic().getEncoded();
        PublicKey publicKey = byteArrayToPublickey(Hex.decode("046456CC2649C6216281EE91DCDC5A75C8E92706C3C9B85362796E8E8277BB34A663C11AF6619F6C5A452626EF2703BE187681A816D988467DED48D17E5E54F613"));
        byte[] data = Hex.decode("B0448E89946BB21EC649FDF3BA46296602182849FBE2D329AAF843DE0D7CA73F");
        BigInteger bigInteger = new BigInteger("105346645824813091583495808130328573841359553048162952770093773822631478486079");
        PrivateKey privateKey = byteArrayToPrivateKey(Hex.decode("50E7324D208DC091C089FB98FAEC64468EAE6789B0F707EDFE86EF7CB754DAEA"));
        System.out.println("随机数16进制输出:" + Hex.toHexString(BigIntegertoByteArray(bigInteger)));
        byte[] encryptData = sm2.encryptOld(data, publicKey);
        System.out.println("按照C1||C2||C3的方式加密后的数据:" + Hex.toHexString(encryptData));
        System.out.println("Der编码后的加密数据：" + Hex.toHexString(SM2.encodeSM2CipherToDER(encryptData)));
        byte[] content = sm2.decryptOld(encryptData, privateKey);
        System.out.println(Hex.toHexString(content));
        System.out.println("按照C1||C3||C2的方式加密后的数据:" + Hex.toHexString(SM2.changeC1C2C3ToC1C3C2(encryptData)));
        System.out.println("原数据:" + Hex.toHexString(data));
        byte[] c1c3c2 = sm2.encryptNew(data, publicKey);
        System.out.println("按照C1||C3||C2的方式加密后的数据:" + Hex.toHexString(c1c3c2));
        byte[] plainText = sm2.decryptNew(c1c3c2, privateKey);
        System.out.println("解密后的数据:" + Hex.toHexString(plainText));
        System.out.println("========================基于国密检测工具SM2数据加密验证测试=============结束=============");
    }

    @Test
    public void sign() throws SignException, NoSuchAlgorithmException, InvalidKeySpecException {
        String data = "this is test data2344444444444444444444444444444440--------8934753849444444444444345555555555555555";
        System.out.println("原文：" + Hex.toHexString(data.getBytes()));
        System.out.println("数据长度：" + data.getBytes().length);
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
        System.out.println("私钥getencode长度" + keyPair.getPrivate().getEncoded().length);
        BCECPublicKey bcecPublicKey = (BCECPublicKey) keyPair.getPublic();
        System.out.println("公钥长度：" + bcecPublicKey.getQ().getEncoded(false).length);
        System.out.println("公钥内容：" + Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));
        boolean result = sm2.verify(data.getBytes(), keyPair.getPublic(), signature, SIGNATURE_ALGORITHM);
        byte[] bytes = keyPair.getPrivate().getEncoded();
        System.out.println("私钥的字节数组形式:" + Hex.toHexString(bytes));
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        byte[] sign = sm2.sign("123".getBytes(StandardCharsets.UTF_8), privateKey, "SM3WithSM2");
        System.out.println(Hex.toHexString(sign));
        System.out.println("verify result:" + result);
    }


    @Test
    public void decrypt() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, SignException, EncryptException {
        String sm4keyHex = "19c15f302a65db3d827524d69bf88df1";
        SM4 sm4 = new SM4();
        byte[] sm4key = Hex.decode(sm4keyHex);
        String pkBase64 = "BJFAshIBFQvwlSU9ZOgnm204iOskYeccwo8qB0Nu7IM1UISBP2kzRUmF13m7rIgN3e0xlDl2zM7Ydd2VSll1rCw=";
        String skBase64 = "MIGIAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG4wbAIBAQIhAIarnTkuivOmR1KZIjjshnAlW3Y3lvm72aT2OiNfgmK5oUQDQgAEkUCyEgEVC/CVJT1k6CebbTiI6yRh5xzCjyoHQ27sgzVQhIE/aTNFSYXXebusiA3d7TGUOXbMzth13ZVKWXWsLA==";

        byte[] ensk = Base64.decode("WHO3GNnTvO8xSC9r4GIhRZUzkK3yByJ7oHi4H+a24oh/5RQ5Yq90ScJR63zZPtZtNzMUHyy0U2s7+k9DTwVqCdKs7Uo8Jh7u+A2XkELgGYiMusMNTKvJgpyYDfct4sfREv2uwtRGPhUSAIB8jGxN4TO5iMGmHHe6yRH6RWmLeuX0E0j4r3gR2BODLLeoJx6B");

        byte[] decsk = sm4.decrypt("SM4/ECB/PKCS5Padding", sm4key, null, ensk);

        System.out.println(Base64.toBase64String(decsk));
        Assert.assertEquals(skBase64, Base64.toBase64String(decsk));
        byte[] pk = Base64.decode(pkBase64);
        byte[] sk = Base64.decode(skBase64);
        System.out.println("私钥长度：" + sk.length);
        System.out.println("公钥：" + Hex.toHexString(pk));
        System.out.println("私钥：" + Hex.toHexString(sk));

        PrivateKey privateKey = byteArrayToPrivateKey(Hex.decode("86ab9d392e8af3a64752992238ec8670255b763796f9bbd9a4f63a235f8262b9"));
//        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(sk);
//        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
//        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        byte[] sign = sm2.sign("123".getBytes(), privateKey, "SM3WithSM2");
        PublicKey publicKey = byteArrayToPublickey(pk);
        boolean value = sm2.verify("123".getBytes(), publicKey, sign, "SM3WithSM2");
        System.out.println("验证结果：" + value);
        System.out.println(Hex.toHexString(sign));


    }


    @Test
    public void verfiy() throws SignException {
        String pkBase64 = "BJFAshIBFQvwlSU9ZOgnm204iOskYeccwo8qB0Nu7IM1UISBP2kzRUmF13m7rIgN3e0xlDl2zM7Ydd2VSll1rCw=";
        String signBase64 = "lpiGFOsHlZFs9dR1a0v2pdUrtk/CUI441+/9+OMALfe45rn7zin9tIXxKd2dZUNbvtmFprr1bYSM+ShUOzs57w==";
        String hashBase64 = "+Lsil6EQReEJAGBrc/bP9GdOyACRVRAu+sWQVCVQIJ8=";

        byte[] pk = Base64.decode(pkBase64);
        byte[] sign = Base64.decode(signBase64);
        byte[] hash = Base64.decode(hashBase64);
        PublicKey publicKey = byteArrayToPublickey(pk);
        System.out.println("pk:" + Hex.toHexString(pk));
        System.out.println(pk.length);
        System.out.println("sign:" + Hex.toHexString(sign));
        System.out.println("hash:" + Hex.toHexString(hash));

        boolean result = sm2.verify(hash, publicKey, Hex.decode("304602210096988614eb0795916cf5d4756b4bf6a5d52bb64fc2508e38d7effdf8e3002df7022100b8e6b9fbce29fdb485f129dd9d65435bbed985a6baf56d848cf928543b3b39ef"), "SM3WithSM2");
        System.out.println(result);
    }


    @Test
    public void test() throws SignException, HashException {
        String pkString = "042818208dae616f5a6b97dc2bf72e0d6204d9fde71ab6adc546cebc43da524250a958bb15ac939bad10c5a696f8ceaf007a7f6cdd089304d9ff7e670c37a68e0f";
        byte[] pk = Hex.decode(pkString);
        PublicKey publicKey = byteArrayToPublickey(pk);
        byte[] data = Hex.decode("0abb060a6108031a0c08d7ccb9fd0510c0c3aef50222026f612a40653963303734653262643766326362326631346532613761343364616236623834303362313964306637643835396431336431653561633462313036656563363a0912071205617564697412d5050ab8050a074f7267314d535012ac052d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494942797a43434158696741774942416749554a5157384e36774f67526a58615a567979707132364a536934497777436759494b6f45637a315542673355770a5754456b4d434947413155454177776262334a6e4d53357a5957317762475575616e56736232356e593268686157347562334a6e4d51737743515944565151470a45774a44546a456b4d434947413155454367776262334a6e4d53357a5957317762475575616e56736232356e593268686157347562334a6e4d423458445449770a4d5441794e7a41794d546b774d566f58445451774d5441794d6a41794d546b774d566f775a7a45724d436b4741315545417777695957527461573478514739790a5a7a4575633246746347786c4c6d7031624739755a324e6f59576c754c6d39795a7a454c4d416b474131554542684d43513034784b7a417042674e5642416f4d0a496d466b62576c754d554276636d63784c6e4e68625842735a53357164577876626d646a6147467062693576636d63775754415442676371686b6a4f505149420a4267677167527a50565147434c514e434141516f4743434e726d4676576d7558334376334c673169424e6e3935787132726356477a727844326c4a43554b6c590a757857736b357574454d576d6c766a4f7277423666327a64434a4d453266392b5a777733706f34506f784177446a414d42674e5648524d45425441444151482f0a4d416f4743437142484d395641594e31413045414c716f42596d51392b6c5776715376746f666e762f436d6b2f596d4f652f2b34714d6c62744d7931417450320a654c596b494867706e316f61463653474f69656263564874637a5069516b3850723672576f796f7077773d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a1218137e27a309fe0d825f5fc678ece17311d710fe9db4a4805f128f1a0a8c1a0ad5050ab8050a074f7267314d535012ac052d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494942797a43434158696741774942416749554a5157384e36774f67526a58615a567979707132364a536934497777436759494b6f45637a315542673355770a5754456b4d434947413155454177776262334a6e4d53357a5957317762475575616e56736232356e593268686157347562334a6e4d51737743515944565151470a45774a44546a456b4d434947413155454367776262334a6e4d53357a5957317762475575616e56736232356e593268686157347562334a6e4d423458445449770a4d5441794e7a41794d546b774d566f58445451774d5441794d6a41794d546b774d566f775a7a45724d436b4741315545417777695957527461573478514739790a5a7a4575633246746347786c4c6d7031624739755a324e6f59576c754c6d39795a7a454c4d416b474131554542684d43513034784b7a417042674e5642416f4d0a496d466b62576c754d554276636d63784c6e4e68625842735a53357164577876626d646a6147467062693576636d63775754415442676371686b6a4f505149420a4267677167527a50565147434c514e434141516f4743434e726d4676576d7558334376334c673169424e6e3935787132726356477a727844326c4a43554b6c590a757857736b357574454d576d6c766a4f7277423666327a64434a4d453266392b5a777733706f34506f784177446a414d42674e5648524d45425441444151482f0a4d416f4743437142484d395641594e31413045414c716f42596d51392b6c5776715376746f666e762f436d6b2f596d4f652f2b34714d6c62744d7931417450320a654c596b494867706e316f61463653474f69656263564874637a5069516b3850723672576f796f7077773d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a1218298db5a4876a684302909b5d76c60a97ae5b74f2c584abee12b1140a93030a90030a8d0308041207120561756469741aff020a04736176650af6027b22616374696f6e64657461696c223a22e7bd91e7bb9ce79b91e6b58be9a1b5e99da2e69fa5e79c8be8aebee5a487e8afa6e683853a3139302e3131362e3132382e3931e69eaae79083e88194e58aa8222c22616374696f6e726573756c74223a22e68890e58a9f222c22616374696f6e74797065223a22e5afbce587ba457863656c222c22617070636f6465223a226f61222c22617564697474696d65223a22323032302d31312d31332031343a34353a3030222c226d6f64756c656e616d65223a22e697a5e5b8b8e5b7a1e6a380222c227361766574696d65223a22323032302d31312d31332031343a34353a3030222c227365727665726970223a223139322e3136382e312e38222c22737973636f6465223a226f61222c227472616e73616374696f6e6e6f223a226633386665383734333735353432313538393865376366333637613239343132222c22757365726970223a2231302e302e302e37222c22757365726e616d65223a22e699bae58b87227d1298110a950b0a204d45e1fb2584b5a6d5aeefa384add736f4c807ed09259e75eeabf7181776b53212f00a0aab0312a8030a056175646974129e031a9b030a2063666530646261303163383334383039386531386162376436633566666530341af6027b22616374696f6e64657461696c223a22e7bd91e7bb9ce79b91e6b58be9a1b5e99da2e69fa5e79c8be8aebee5a487e8afa6e683853a3139302e3131362e3132382e3931e69eaae79083e88194e58aa8222c22616374696f6e726573756c74223a22e68890e58a9f222c22616374696f6e74797065223a22e5afbce587ba457863656c222c22617070636f6465223a226f61222c22617564697474696d65223a22323032302d31312d31332031343a34353a3030222c226d6f64756c656e616d65223a22e697a5e5b8b8e5b7a1e6a380222c227361766574696d65223a22323032302d31312d31332031383a35363a3234222c227365727665726970223a223139322e3136382e312e38222c22737973636f6465223a226f61222c227472616e73616374696f6e6e6f223a226366653064626130316338333438303938653138616237643663356666653034222c22757365726970223a2231302e302e302e37222c22757365726e616d65223a22e699bae58b87227d1aaf0708c80112d3037b226d657373616765223a2269643a7b5c22616374696f6e64657461696c5c223a5c22e7bd91e7bb9ce79b91e6b58be9a1b5e99da2e69fa5e79c8be8aebee5a487e8afa6e683853a3139302e3131362e3132382e3931e69eaae79083e88194e58aa85c222c5c22616374696f6e726573756c745c223a5c22e68890e58a9f5c222c5c22616374696f6e747970655c223a5c22e5afbce587ba457863656c5c222c5c22617070636f64655c223a5c226f615c222c5c22617564697474696d655c223a5c22323032302d31312d31332031343a34353a30305c222c5c226d6f64756c656e616d655c223a5c22e697a5e5b8b8e5b7a1e6a3805c222c5c227361766574696d655c223a5c22323032302d31312d31332031383a35363a32345c222c5c2273657276657269705c223a5c223139322e3136382e312e385c222c5c22737973636f64655c223a5c226f615c222c5c227472616e73616374696f6e6e6f5c223a5c2263666530646261303163383334383039386531386162376436633566666530345c222c5c227573657269705c223a5c2231302e302e302e375c222c5c22757365726e616d655c223a5c22e699bae58b875c227d222c22737461747573223a3230302c2273756363657373223a747275657d1ad3037b226d657373616765223a2269643a7b5c22616374696f6e64657461696c5c223a5c22e7bd91e7bb9ce79b91e6b58be9a1b5e99da2e69fa5e79c8be8aebee5a487e8afa6e683853a3139302e3131362e3132382e3931e69eaae79083e88194e58aa85c222c5c22616374696f6e726573756c745c223a5c22e68890e58a9f5c222c5c22616374696f6e747970655c223a5c22e5afbce587ba457863656c5c222c5c22617070636f64655c223a5c226f615c222c5c22617564697474696d655c223a5c22323032302d31312d31332031343a34353a30305c222c5c226d6f64756c656e616d655c223a5c22e697a5e5b8b8e5b7a1e6a3805c222c5c227361766574696d655c223a5c22323032302d31312d31332031383a35363a32345c222c5c2273657276657269705c223a5c223139322e3136382e312e385c222c5c22737973636f64655c223a5c226f615c222c5c227472616e73616374696f6e6e6f5c223a5c2263666530646261303163383334383039386531386162376436633566666530345c222c5c227573657269705c223a5c2231302e302e302e375c222c5c22757365726e616d655c223a5c22e699bae58b875c227d222c22737461747573223a3230302c2273756363657373223a747275657d220e120561756469741a05312e302e3012fd050ab8050a074f7267314d535012ac052d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494942797a43434158696741774942416749554a5157384e36774f67526a58615a567979707132364a536934497777436759494b6f45637a315542673355770a5754456b4d434947413155454177776262334a6e4d53357a5957317762475575616e56736232356e593268686157347562334a6e4d51737743515944565151470a45774a44546a456b4d434947413155454367776262334a6e4d53357a5957317762475575616e56736232356e593268686157347562334a6e4d423458445449770a4d5441794e7a41794d546b774d566f58445451774d5441794d6a41794d546b774d566f775a7a45724d436b4741315545417777695957527461573478514739790a5a7a4575633246746347786c4c6d7031624739755a324e6f59576c754c6d39795a7a454c4d416b474131554542684d43513034784b7a417042674e5642416f4d0a496d466b62576c754d554276636d63784c6e4e68625842735a53357164577876626d646a6147467062693576636d63775754415442676371686b6a4f505149420a4267677167527a50565147434c514e434141516f4743434e726d4676576d7558334376334c673169424e6e3935787132726356477a727844326c4a43554b6c590a757857736b357574454d576d6c766a4f7277423666327a64434a4d453266392b5a777733706f34506f784177446a414d42674e5648524d45425441444151482f0a4d416f4743437142484d395641594e31413045414c716f42596d51392b6c5776715376746f666e762f436d6b2f596d4f652f2b34714d6c62744d7931417450320a654c596b494867706e316f61463653474f69656263564874637a5069516b3850723672576f796f7077773d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a12409f7fe3cf7bcd751761cac1aabb753b9e6ce69e0fe14b69a7444283e7e048cdfb6cab5c034906c25b32a6e8e85ff44ab5cbb5ae2ac733131e1f21a80370478214");

        byte[] digest = new SM3().hash(data);
        //System.out.println("摘要值："+Hex.toHexString(digest));
        byte[] sign = Hex.decode("96f5f5a079963619a82a49ea3143d286172bcab14c768a4fc9c00b8c3aa3028516453911e4744386e942c6055e89d0bbb3a3f84a6bd5039209434b967929ff66");
        byte[] decode = GmUtil.rsPlainByteArrayToAsn1(sign);
        //  System.out.println("转换为Der格式的16进制:"+Hex.toHexString(decode));
        boolean result = sm2.verify(data, publicKey, decode, "SM3WithSM2");
        System.out.println(result);
    }


    @Test
    public void stest() throws SignException {
        String pkString = "049140b21201150bf095253d64e8279b6d3888eb2461e71cc28f2a07436eec83355084813f6933454985d779bbac880ddded31943976ccced875dd954a5975ac2c";
        byte[] pk = Hex.decode(pkString);
        PublicKey publicKey = byteArrayToPublickey(pk);
        byte[] data = Hex.decode("f8bb2297a11045e10900606b73f6cff4674ec8009155102efac590542550209f");
        byte[] decode = GmUtil.rsPlainByteArrayToAsn1(Hex.decode("96988614eb0795916cf5d4756b4bf6a5d52bb64fc2508e38d7effdf8e3002df7b8e6b9fbce29fdb485f129dd9d65435bbed985a6baf56d848cf928543b3b39ef"));
        boolean result = sm2.verify(data, publicKey, decode, "SM3WithSM2");
        System.out.println("验证结果：" + result);
    }


    @Test
    public void deviceTest() throws SignException, HashException {
        byte[] sk = Hex.decode("4cc9a79a3cb418eaf012f14788e7a14656fa0c65fd4f187c77afb5b03d65396a");
        byte[] pk = Hex.decode("041b2ff24f8e4a5de48e2d561179b8287fab0b5d48df1d8ff72d76ab614c5892496b0bf129360d371b2cb2a88688974bf57d13f6be263a3558137402670d7cb8a1");
        PublicKey publicKey = byteArrayToPublickey(pk);
        byte[] sign = Hex.decode("2eaaf9a0a9e58e569bf12224a3f09af6be81f94daa9d29326ceea920241a49f60a7cb13bd92b3df4ab9dea9ea33e68ec0d8aa514f51cb2c2743cfc5b6ee457f9");
        byte[] data = "398f384de5132126d8c358f2769cad6e".getBytes(StandardCharsets.UTF_8);
        byte[] aa = Hex.decode("398f384de5132126d8c358f2769cad6e");
        SM3 sm3 = new SM3();
        byte[] hash = sm3.hash(aa);
        GmUtil.rsPlainByteArrayToAsn1(sign);
        boolean result = sm2.verify(aa, publicKey, GmUtil.rsPlainByteArrayToAsn1(sign), "SM3WithSM2");
        System.out.println(result);
    }


    @Test
    public void certVerify() throws SignException, CertificateException, FileNotFoundException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        // String random_Base64="YlYzSERHeW1GV1l3ZTcydTl3b2wyZ2NlQkxOTWRJTHhQaU8wTUxtOW5yNE1TbFIzNFdxVlhQNEVTQWdob1ZvanFDdnhFZE81RFN0cGRIVXdFOUZKbUl0Zk12dDg3ODFkdytBdCtHby9vUDVSV3pDZFhXckpLZVpKTUYxcHZDaW9IUFY4c2tPdktGay9QTHJXNG1xZDFEcVlvbmg1UkI0OUNISWp0UnFSUW9QZjN0UXM2Nks4Tkk1ZXk1T2xuZWpkTHdYWi94eWNheVBIQ2ozZGR0VkF6V2hqNGkzRWFYNE5UOEpPdDg2Q2FQVTZzbjdZQVlPVzJZTHN6WVFRS2hqVW1lb0VVR3dpNlgxQXV1eWFRZWlyMFlPWC81N1NIblppeVN5dzVKcVlJODQwTUZRYWEyVjV0NGVyRU5GRy9uaFJlNUJmUFhUTDVrR2xTajMzVVRGL2ZBPT0=";
        String random_Base64_plain = "OTVwQmwxRTJKY3Ezejkvc2I5WjZuTGNRc2xMSTFDYUYzcm9rczVzU00yc25OSzEzbmcyTld4NkdhOG1GVWNIR05HUnpFSkt0Mng2SktoNE1NaXUxeXRKUS9Ya2JLTk5hZU5GamFQN284SkNSL0pwMVVOc2U1ZnZwdUhLSW8vamNkQ0xEY0Vtd2NOYnFIakp3LzBGK3ZkN3pMTlBQVUFWUStVQlpUR3JaUDg4TG9saTZwaW5zZWFsOXJmbU85TFRCQUVwNFlwTHByUEFpWis5NzNCTXFFVm9YTkdIbldhT09SeHFqWHozTWtEVTRYdUV5TFlFZ0t2ZGRHckU1QkNwWUhsemN4SzcrbXFJdWZ4aUFTbmlVaXdOMkIwTFNGR1BYOUZnTWFGemtBeHkvVnphWXdVWTlBU3ZhdFRyYmtmL05rcjVFVUFxd3FPWStwQzJpWWVpSTNBPT0=";

        String sign_Base64 = "MEQCIAWC1WDvoXTD5PBiYZ+FxaRsLijvZqNZ9fspGplafpujAiBvHYcS6mjHAbFM2GMTINreni1UlBPLpujwACVQMjkd4A==";
        byte[] random = java.util.Base64.getDecoder().
                decode(random_Base64_plain);
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        InputStream inputStream = new FileInputStream("D:\\code\\java-code\\crypto\\test-cert\\guan.pem");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(inputStream);
        PublicKey publicKey = certificate.getPublicKey();
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        System.out.println("证书公钥：" + Hex.toHexString(bcecPublicKey.getQ().getEncoded(false)));
        byte[] sign = java.util.Base64.getDecoder().decode(sign_Base64);
        boolean result = sm2.verify(random, publicKey, sign, "SM3WithSM2");
        System.out.println("验签结果:" + result);
    }


    @Test
    public void sanTest() throws SignException, EncryptException {

        String pk = "BJFAshIBFQvwlSU9ZOgnm204iOskYeccwo8qB0Nu7IM1UISBP2kzRUmF13m7rIgN3e0xlDl2zM7Ydd2VSll1rCw=";
        String sk = "WHO3GNnTvO8xSC9r4GIhRZUzkK3yByJ7oHi4H+a24oh/5RQ5Yq90ScJR63zZPtZtNzMUHyy0U2s7+k9DTwVqCdKs7Uo8Jh7u+A2XkELgGYiMusMNTKvJgpyYDfct4sfREv2uwtRGPhUSAIB8jGxN4TO5iMGmHHe6yRH6RWmLeuX0E0j4r3gR2BODLLeoJx6B";
        byte[] pubKey = java.util.Base64.getDecoder().
                decode(pk);
        byte[] priKey = java.util.Base64.getDecoder().
                decode(sk);
        System.out.println("公钥：" + Hex.toHexString(pubKey));
        System.out.println("私钥：" + Hex.toHexString(priKey));
        System.out.println("私钥加密后的长度：" + Hex.toHexString(priKey).length());
        byte[] sm4key = Hex.decode("19c15f302a65db3d827524d69bf88df1");

        //解密后的私钥本身
        byte[] skp = Hex.decode("86ab9d392e8af3a64752992238ec8670255b763796f9bbd9a4f63a235f8262b9");

        SM4 sm4 = new SM4();
        byte[] plain = sm4.decrypt("SM4/ECB/PKCS5Padding", sm4key, null, priKey);
        System.out.println(Hex.toHexString(plain));
        System.out.println(plain.length);
        PrivateKey privateKey = sm2.genKeyPair(0).getPrivate();
        System.out.println(privateKey.getEncoded().length);


        PrivateKey privateKey1 = byteArrayToPrivateKey(skp);
        byte[] testData = "124".getBytes(StandardCharsets.UTF_8);
        PublicKey publicKey = byteArrayToPublickey(pubKey);
        byte[] sign = sm2.sign(testData, privateKey1, "SM3WithSM2");
        boolean result = sm2.verify(testData, publicKey, sign, "SM3WithSM2");
        System.out.println("验签结果：" + result);
    }


    @Test
    public void qimingTest() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("D:\\code\\java-code\\crypto\\test-cert\\111.pem"));
        PublicKey publicKey = certificate.getPublicKey();
        byte[] testData = java.util.Base64.getDecoder().decode("lPJVo2GJC9JtqYEoD8/CYA011cQTAF7TjLWU7DFM2i0=");
        System.out.println("摘要16进制字符串：" + Hex.toHexString(testData));

        String random = "15300659017816261783988831211042";
        String base64_Random = Base64.toBase64String("15300659017816261783988831211042".getBytes(StandardCharsets.UTF_8));
        System.out.println("随机数的base64字符串：" + base64_Random);
        byte[] randomBase64 = Base64.decode(random);
        SM3 sm3 = new SM3();

        byte[] digest = sm3.hash(random.getBytes(StandardCharsets.UTF_8));
        System.out.println("随机数计算SM3摘要值：" + Hex.toHexString(digest));
        byte[] sign = java.util.Base64.getDecoder().decode("zWyTDO3dXJyNDnF2k4V+zHViNXRV2R0kKmqJiTsnXnE8gSO2hhDuJRcIJE1hDyTxoxH82Q6/FgTXKHLsxL8Ujw==");
        byte[] newSign = GmUtil.rsPlainByteArrayToAsn1(sign);
        System.out.println(Hex.toHexString(newSign));
        boolean result = sm2.verify(random.getBytes(StandardCharsets.UTF_8), publicKey, newSign, "SM3WithSM2");
        System.out.println("验签结果：" + result);
    }


    @Test
    public void svTest() throws SignException {
        byte[] sk = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg5IeFMDC5amP3JlRQeywQMIC9JCBPaYtLZkNjHlWe5XOgCgYIKoEcz1UBgi2hRANCAARCV2v0gsg9q42nzHPhULSsdDhBOtFHDMsRF0kyUt/QKb7lw30WgApaVluDHUtbXZTLTtAK1dRvsXoHnNEE2p3l");
        System.out.println(sk.length);
        byte[] pk = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEQldr9ILIPauNp8xz4VC0rHQ4QTrRRwzLERdJMlLf0Cm+5cN9FoAKWlZbgx1LW12Uy07QCtXUb7F6B5zRBNqd5Q==");
        System.out.println("公钥:" + Hex.toHexString(pk));
        System.out.println("公钥长度:" + pk.length);
        byte[] sign = Base64.decode("MEQCIANKvq14FYlw3N9YOHo1jvA4gPQXw9+MWifLYk7H0cedAiAN+NXLZ+U2Qs76mtbNyOhiYnyKpHDy/bpPDzbAK0LN0A==");
        byte[] pkk = Hex.decode("0442576BF482C83DAB8DA7CC73E150B4AC7438413AD1470CCB1117493252DFD029BEE5C37D16800A5A565B831D4B5B5D94CB4ED00AD5D46FB17A079CD104DA9DE5");
        System.out.println(pkk.length);
        PublicKey publicKey = byteArrayToPublickey(pkk);
        System.out.println("签名值：" + Hex.toHexString(sign));
        boolean result = sm2.verify("00000000000000000000000000000000".getBytes(), publicKey, sign, SIGNATURE_ALGORITHM);
        System.out.println(result);
    }


    /**
     * 基于检测机构提供的数据进行验证
     *
     * @throws SignException
     */
    @Test
    public void GmDataTest() throws SignException {
        byte[] pk = Hex.decode("049B483197475D8C20E73F8108265FF0EB99C99F858A539F7BEAAA2699F2DF840ABECE3B4AADC90BF3C8ED7157B2AE06CC7390263BC5585A07CD2D138B249D64D8");
        byte[] sk = Hex.decode("190E54D3A4967B25BD0E8640B8DF33867998E4606AF3D1875FC84A71182D9C84");
        byte[] sign = Hex.decode("C515198E50F335818338A8EF9574D6670C5801C517AF4F74523829B338B51340BEBEE777587367E7EA0675C145A02360785C365EE49DEB300347B3F72F4A234F");
        byte[] text = Hex.decode("F7EA096E6ADE002BEDFDF60325ECEBED7446F882084F35376079E4CB0226C7E5");
        PublicKey publicKey = byteArrayToPublickey(pk);
        byte[] decode = GmUtil.rsPlainByteArrayToAsn1(sign);
        boolean result = sm2.verify(text, publicKey, decode, SIGNATURE_ALGORITHM);
        System.out.println(result);
    }


    /**
     * C1C2C3
     * 标准国密加密数据验证时，需要密文前加上04，私钥加上00
     *
     * @throws SignException
     */
    @Test
    public void sm2DecOldTest() throws SignException {
        byte[] pk = Hex.decode("b43a0ec1e2664821f8cd44497ac39e5c9e873fa6a402df02837d8e60cb87e5d6e702fa055cb58e682f344d7409a8a8bb6991e56df4af3dc3b91d32545120174f");
        byte[] sk = Hex.decode("7218a3a4318250aa9b4118c7ff6e96ed23ea68dd86432ee14bdaf5100b860246");
        byte[] enc = Hex.decode("04bf3bdb8b0211c4424d7434c63b514b7fb62eb7cb910fa9790fdb36507c0056114399b2b16d255c90916b01ff801dbf2457689a1bade14113144eb7254c29053c931ce66a9182e2393096f19259dfcbbcef5ed3757f12c0d2e9c3f1385e6c30ca201ea07bc6d49b78236e1bf872d414ff");
        PrivateKey privateKey = byteArrayToPrivateKey(sk);
        byte[] context = sm2.decryptOld(enc, privateKey);
        System.out.println(Hex.toHexString(context));
    }

    /**
     * C1C3C2数据验证
     * 标准国密加密数据验证时，需要密文前加上04，私钥加上00
     *
     * @throws SignException
     */
    @Test
    public void sm2DecNewTest() throws SignException {
        byte[] pk = Hex.decode("C8D209439CFD2D05581AA20EAA4A20574E8D9F530E6258DF877614EEE7E6F7FD1803C4EB4ADC71CD0C2EF94132F7E4B56B96B933CA0141326ACB0437DD322866");
        byte[] sk = Hex.decode("0250BD7CA357BAD4019AD769F4259D77D45030F762240505A12DF02455723C5D");
        byte[] enc = Hex.decode("046d723b0de6d0425cacc0b978771648118c6b2f329a3317234c7ecea79f9fad80a437b8131a50ca413d73c34b805d1e3c4fc812de32a503f90fe0b347967c108ccdeaa09a579aaf042786b23fff2dde972f2584256bd55f45e794fc48df3fafe86df5406e061f7e1c491af6f5d29c6804794e9d561d6726f91641905557309625");
        //期望值
        byte[] expected = Hex.decode("8BB568ED8A286EDD4977A5EF2915AC14AC8A3337261E8638AEB8D2861064E8C5");
        PrivateKey privateKey = byteArrayToPrivateKey(sk);
        byte[] context = sm2.decryptNew(enc, privateKey);
        Assert.assertArrayEquals(expected, context);
    }


    @Test
    public void aa() {
        byte[] s = "1234567812345678".getBytes();
        //String ID=new String(Hex.decode("B0448E89946BB21EC649FDF3BA46296602182849FBE2D329AAF843DE0D7CA73F"));
        System.out.println(Hex.toHexString(s));
    }


}
