package org.github.cert;


import junit.framework.TestCase;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.github.algorithm.gm.sign.SM2;
import org.github.algorithm.international.sign.RSA;
import org.github.common.utils.CertUtil;
import org.github.common.utils.CryptoUtil;
import org.github.common.utils.FileUtil;

import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;


import java.util.Date;

public class GenCertTest extends TestCase {
    private GenCert genCert;

    public void setUp() throws Exception {
        genCert = new GenCert();
    }

    public void testGenGmCaRootCert() throws Exception {
        System.out.println("-----------------生成国密根证书-----------------");
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.genKeyPair(0);
        new GenCert().genGmCaRootCert(keyPair, "C=CN,CN=GM ROOT CA,S=Guangdong,L=shenzhen,O=TopChain,OU=dep", 20, "www.test.com", "123@gmail.com");
        System.out.println();
    }

    public void testGenStandardCaRootCert() throws Exception {
        System.out.println("-----------------生成标准根证书-----------------");
        RSA rsa = new RSA();
        KeyPair keyPair = rsa.genKeyPair(2048);
        X509Certificate caRootCert = new GenCert().genStandardCaRootCert(true, keyPair, "sha256withRSA", "C=CN,CN=GM ROOT CA,S=Guangdong,L=shenzhen,O=TopChain,OU=dep", 10, "www.rsa.com", "abc@qq.com");
        FileUtil.writeFile("StandardCaRootCert.pem", CryptoUtil.convertBase64Pem(caRootCert));
    }

    public void testGenCertWithCaSign() throws Exception {
        System.out.println("-----------------生成国密用户证书-----------------");
        SM2 sm2 = new SM2();
        KeyPair keyPair1 = sm2.genKeyPair(0);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
        Certificate caRootCert = certificateFactory.generateCertificate(new FileInputStream("GmCARootCert.cer"));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(FileUtil.readFile("GmCAPrikey"));
        PrivateKey caPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        X509Certificate certificate = new GenCert().genCertWithCaSign((X509Certificate) caRootCert, caPrivateKey, keyPair1, "SM3withSM2", "CN=cms-web", 10, "www.aaa.com", "3434@qq.com");
        System.out.println("-----------------证书验证-----------------");
        certificate.checkValidity(new Date());
        certificate.verify(caRootCert.getPublicKey());
    }

    public void testGenStandardtCertWithCaSign() throws Exception {
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.genKeyPair(0);
        System.out.println(CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
    }
}
