package org.github.cert;

import org.bouncycastle.util.encoders.Hex;
import org.github.algorithm.international.sign.RSA;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.common.utils.CryptoUtil;
import org.github.common.utils.FileUtil;
import org.junit.Test;
import sun.security.x509.X509CRLImpl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.*;

import static org.junit.Assert.*;

public class GenCRLTest {
    private static CryptoLog log = CryptoLogFactory.getLog(GenCRLTest.class);

    @Test
    public void genCaCRL() throws Exception {

        KeyPair keyPair = CryptoUtil.parseKeyPairFromPem("StandardCaPriKey.pem");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509Certificate caRootCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardCaRootCert.pem"));
        X509Certificate userCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardUser1Cert.pem"));
        //unspecified 0	未指定
        //keyCompromise 1	私钥泄漏
        //cACompromise 2	CA 私钥可能泄漏
        //affiliationChanged 3	组织变化，隶属关系变更
        //superseded 4	被取代
        //cessationOfOperation 5	CA 停用
        //certificateHold 6	临时吊销
        //removeFromCRL 7	使用 certificateHold 吊销的证书，可以用 removeFromCRL 取消吊销
        //privilegeWithdrawn 8	因证书某权限被撤销而吊销
        //aACompromise 9	indicates that it is known or suspected that aspects of the AA validated in the attribute certificate have been compromised
        X509CRL crl = new GenCRL().genCaCRL(keyPair.getPrivate(), caRootCert, userCert.getSerialNumber(), 1, "sha256withRSA");
        FileUtil.writeFile("standardCaCRL.crl", CryptoUtil.convertBase64Pem(crl));
        log.info("---crl验证-----");
        PublicKey publicKey=caRootCert.getPublicKey();
//        KeyPair kp= new RSA().genKeyPair(2048);
        crl.verify(publicKey);
        boolean isRevoked = crl.isRevoked(userCert);
        log.info("该证书是否被吊销：" + isRevoked);
    }


    @Test
    public void vaildCert() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509CRL crl = (X509CRL) certificateFactory.generateCRL(new FileInputStream("standardCaCRL.crl"));
        X509Certificate userCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardUserCert.pem"));

       // crl.verify(userCert.getPublicKey());

        boolean isRevoked = crl.isRevoked(userCert);
        X509CRLEntry x509CRLEntry = crl.getRevokedCertificate(userCert.getSerialNumber());
        if (x509CRLEntry != null) {
            System.out.println("Revoked");
        }
       log.info("该证书是否被吊销：" + isRevoked);
    }

    @Test
    public void updateCRL() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509Certificate caRootCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardCaRootCert.pem"));
        X509CRL crl = (X509CRL) certificateFactory.generateCRL(new FileInputStream("standardCaCRL.crl"));
        X509Certificate userCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("StandardUser3Cert.pem"));
        KeyPair keyPair = CryptoUtil.parseKeyPairFromPem("StandardCaPriKey.pem");
        System.out.println(Hex.toHexString(userCert.getSerialNumber().toByteArray()));
        X509CRL x509CRL = new GenCRL().updateCaCRL(crl,keyPair.getPrivate(), caRootCert, userCert.getSerialNumber(), 2);
        FileUtil.writeFile("standardCaCRL.crl", CryptoUtil.convertBase64Pem(x509CRL));



    }

}
