package org.github.cert;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.algorithm.gm.sign.SM2;
import org.github.algorithm.international.sign.RSA;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.common.utils.CryptoUtil;
import org.github.common.utils.FileUtil;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


import java.util.Date;

public class GenCertTest extends TestCase {
    private static CryptoLog log = CryptoLogFactory.getLog(GenCertTest.class);
    private GenCert genCert;

    public void setUp() throws Exception {
        genCert = new GenCert();
    }

    public void testGenGmCaRootCert() throws Exception {
        log.info("-----------------生成国密根证书-----------------");
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.genKeyPair(0);
        X509Certificate gmCaRootCert = new GenCert().genGmCaRootCert(keyPair, "C=CN,CN=GM ROOT CA,S=Guangdong,L=shenzhen,O=TopChain,OU=dep",
                20, "www.test.com", "123@gmail.com");
        log.info("私钥格式：\n" + CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
        FileUtil.writeFile("GmCAPrikey.pem", CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
        //FileUtil.writeFile("GmCAPrikey.pem", CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
        FileUtil.writeFile("GmCARootCert.pem", CryptoUtil.convertBase64Pem(gmCaRootCert));
    }

    public void testGenStandardCaRootCert() throws Exception {
        log.info("-----------------生成标准根证书-----------------");
        RSA rsa = new RSA();
        KeyPair keyPair = rsa.genKeyPair(2048);
        X509Certificate caRootCert = new GenCert().genStandardCaRootCert(true, keyPair, "sha256withRSA",
                "C=CN,CN=GM ROOT CA,S=Guangdong,L=shenzhen,O=TopChain,OU=dep",
                10, "www.rsa.com", "abc@qq.com");
        FileUtil.writeFile("StandardCaPriKey.pem", CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
        FileUtil.writeFile("StandardCaRootCert.pem", CryptoUtil.convertBase64Pem(caRootCert));
    }

    public void testGenGmCertWithCaSign() throws Exception {
        log.info("-----------------生成国密用户证书-----------------");
        SM2 sm2 = new SM2();
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = sm2.genKeyPair(0);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
        Certificate caRootCert = certificateFactory.generateCertificate(new FileInputStream("GmCARootCert.pem"));
        KeyPair keyPair1 = CryptoUtil.parseKeyPairFromPem("D:\\code\\java-code\\crypto\\GmCARootCert.pem");
        X509Certificate certificate = new GenCert().genCertWithCaSign((X509Certificate) caRootCert, keyPair1.getPrivate(), keyPair, "SM3withSM2", "CN=verify",
                10, "www.aaa.com", "3434@qq.com");
        certificate.checkValidity(new Date());
        certificate.verify(caRootCert.getPublicKey());
    }

    public void testGenCertWithCaSign() throws Exception {
        log.info("-----------------生成标准用户证书-----------------");
        RSA rsa = new RSA();
        KeyPair keyPair = rsa.genKeyPair(2048);
        log.info("私钥格式：\n" + CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
        KeyPair keyPair1 = CryptoUtil.parseKeyPairFromPem("StandardCaPriKey.pem");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        Certificate caRootCert = certificateFactory.generateCertificate(new FileInputStream("StandardCaRootCert.pem"));
        X509Certificate certificate = new GenCert().genCertWithCaSign((X509Certificate) caRootCert, keyPair1.getPrivate(), keyPair, "sha256withRSA", "CN=test3",
                10, "www.333.com", "333@qq.com");

        FileUtil.writeFile("StandardUser3PrivateKey.pem", CryptoUtil.convertBase64Pem(keyPair.getPrivate()));
        FileUtil.writeFile("StandardUser3Cert.pem", CryptoUtil.convertBase64Pem(certificate));
    }
}
