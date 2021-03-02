package org.github.cert;

import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.common.utils.CryptoUtil;
import org.github.common.utils.FileUtil;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

public class GenCRLTest {
    private static CryptoLog log = CryptoLogFactory.getLog(GenCRLTest.class);

    @Test
    public void genCaCRL() throws Exception {

        KeyPair keyPair = CryptoUtil.parseKeyPairFromPem("StandardCaPriKey.pem");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509Certificate caRootCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardCaRootCert.pem"));
        X509Certificate userCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardUserCert.pem"));

        X509CRL crl = new GenCRL().genCaCRL(keyPair.getPrivate(), caRootCert, userCert.getSerialNumber(), 1, "sha256withRSA");
        FileUtil.writeFile("standardCaCRL.crl", CryptoUtil.convertBase64Pem(crl));
        log.info("---crl验证-----");
        crl.verify(caRootCert.getPublicKey());


        boolean isRevoked = crl.isRevoked(userCert);
        log.info("该证书是否被吊销：" + isRevoked);
    }


    @Test
    public void vaildCert() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509CRL crl  = (X509CRL) certificateFactory.generateCRL(new FileInputStream("standardCaCRL.crl"));
        X509Certificate userCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardUserCert.pem"));
        boolean isRevoked = crl.isRevoked(userCert);
        log.info("该证书是否被吊销：" + isRevoked);

    }
}
