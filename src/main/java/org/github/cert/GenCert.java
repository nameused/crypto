package org.github.cert;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.common.utils.CertUtil;
import org.github.intfs.ICert;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class GenCert implements ICert {
    private static CryptoLog log = CryptoLogFactory.getLog(GenCert.class);

    @Override
    public X509Certificate genGmCaRootCert(KeyPair keyPair, String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        log.info("=============生成国密CA根证书=============");
        X509Certificate cert = CertUtil.genGmCertHelper(keyPair.getPublic(), keyPair.getPrivate(), dn, validData, dnsName, rfc822Name);
        return cert;
    }

    @Override
    public X509Certificate genStandardCaRootCert(boolean isCA, KeyPair keyPair, String signAlgorithm, String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        log.info("=============生成非国密证书=============");
        X509Certificate cert = CertUtil.genStandardCertHelper(isCA, signAlgorithm, keyPair.getPublic(), keyPair.getPrivate(), dn, validData, dnsName, rfc822Name);
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
        log.info("===============生成由CA证书签名的证书===============");
        X509Certificate cert = CertUtil.genCertWithCaSign(caRootCert, caPrivateKey, keyPair.getPublic(), signAlgorithm, dn, validData, dnsName, rfc822Name);
        return cert;
    }
}
