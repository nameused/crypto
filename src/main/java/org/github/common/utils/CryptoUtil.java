package org.github.common.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

/**
 * 加密常用工具类
 */
public class CryptoUtil {

    public static String parseAsn1Data(byte[] data) throws IOException {
        ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(data));
        ASN1Primitive obj = bIn.readObject();
        System.out.println(ASN1Dump.dumpAsString(obj));
        return ASN1Dump.dumpAsString(obj);
    }


    /**
     * 支持将证书、密钥对、CRL转换为可写入pem文件的base64格式
     *
     * @param object
     * @return 字符串
     * @throws Exception
     */
    public static String convertBase64Pem(Object object) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(object);
        }
        return sw.toString();
    }


    /**
     * pem文件中解析秘钥
     *
     * @param filePath
     * @return
     * @throws Exception
     */
    public static KeyPair parseKeyPairFromPem(String filePath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PEMParser pemParser = new PEMParser(new FileReader(filePath));
        Object object = pemParser.readObject();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        KeyPair kp;

        if (object instanceof PEMEncryptedKeyPair) {
            // Encrypted key - we will use provided password
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
            // uses the password to decrypt the key
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build("123".toCharArray());
            kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
        } else {
            // Unencrypted key - no password needed
            PEMKeyPair ukp = (PEMKeyPair) object;
            kp = converter.getKeyPair(ukp);
        }
        // PrivateKey caPrivateKey = kp.getPrivate();
        return kp;
    }


    /**
     * 读取私钥
     *
     * @param skPath
     * @return
     * @throws Exception
     */

    public static PrivateKey parsePrivateKeyFromPem(String skPath) throws Exception {
//        PEMParser pemParser = new PEMParser(new FileReader(skPath));
//        PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
//        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
//        KeyPair kp = converter.getKeyPair(pemKeyPair);
//        return kp.getPrivate();


        PEMParser pemParser = new PEMParser(new FileReader(skPath));
        Object object = pemParser.readObject();
     //
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        KeyPair key;
        if (object instanceof PEMEncryptedKeyPair) {
            System.out.println("Encrypted key - we will use provided password");
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build("12345678".toCharArray());
            key = converter.getKeyPair(((PEMEncryptedKeyPair) object)
                    .decryptKeyPair(decProv));
        } else {
            System.out.println("Unencrypted key - no password needed "+object.getClass().getName());
            key = converter.getKeyPair((PEMKeyPair) object);
        }
        pemParser.close();
        return key.getPrivate();
    }


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey privateKey = CryptoUtil.parsePrivateKeyFromPem("D:\\code\\java-code\\crypto\\GmCAPrikey.pem");
     //   PrivateKey privateKey = CryptoUtil.parsePrivateKeyFromPem("C:\\Users\\zmy\\Desktop\\CA\\sm2.zmy\\zmy_enc_key.pem");
        System.out.println(privateKey.getFormat());
    }
}
