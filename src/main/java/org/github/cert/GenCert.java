package org.github.cert;

import org.bouncycastle.util.encoders.Base64;
import org.github.algorithm.gm.sign.SM2;
import org.github.common.utils.CertUtil;
import org.github.common.utils.FileUtil;
import org.github.intfs.ICert;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

public class GenCert implements ICert {


    @Override
    public X509Certificate genGmCaRootCert(KeyPair keyPair, String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        System.out.println("=============生成国密CA根证书=============");
        System.out.println("CA PrivateKey:" + Base64.toBase64String(keyPair.getPrivate().getEncoded()));
        X509Certificate cert = CertUtil.genGmCertHelper(keyPair.getPublic(), keyPair.getPrivate(), dn, validData, dnsName, rfc822Name);
        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));
        FileUtil.saveFile("GMCAPrikey", keyPair.getPrivate().getEncoded());
        FileUtil.saveFile("GmCARootCert.cer", cert.getEncoded());
        return cert;
    }

    @Override
    public X509Certificate genStandardCaRootCert(boolean isCA, KeyPair keyPair, String signAlgorithm, String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        System.out.println("=============生成非国密证书=============");
        X509Certificate cert = CertUtil.genStandardCertHelper(isCA, signAlgorithm, keyPair.getPublic(), keyPair.getPrivate(), dn, validData, dnsName, rfc822Name);
        System.out.println("CA PrivateKey:" + Base64.toBase64String(keyPair.getPrivate().getEncoded()));
        FileUtil.saveFile("StandardCaRootPrikey", keyPair.getPrivate().getEncoded());
        FileUtil.saveFile("StandardCaRoot.cer", cert.getEncoded());
        return cert;
    }

    /**
     * 由CA证书签发生成证书
     *
     * @param caRootCert
     * @param caPrivateKey
     * @param signAlgorithm
     * @param dn
     * @param validData
     * @param dnsName
     * @param rfc822Name
     * @return
     * @throws Exception
     */
    public X509Certificate genCertWithCaSign(X509Certificate caRootCert, PrivateKey caPrivateKey, KeyPair keyPair, String signAlgorithm, String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        X509Certificate cert = CertUtil.genCertWithCaSign(caRootCert, caPrivateKey, keyPair.getPublic(), signAlgorithm, dn, validData, dnsName, rfc822Name);
        System.out.println("用户证书内容：" + cert.toString());
        System.out.println(" 用户 PrivateKey:" + Base64.toBase64String(keyPair.getPrivate().getEncoded()));
        FileUtil.saveFile("userPrikey", keyPair.getPrivate().getEncoded());
        FileUtil.saveFile("user.cer", cert.getEncoded());
        return cert;
    }

    public static void main(String[] args) throws Exception {



    }
}
