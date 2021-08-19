package org.github.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

public class GenCRL {

    /**
     * 生成CA的CRL列表
     *
     * @param caPrivateKey
     * @param x509Certificate
     * @return
     * @throws Exception
     */
    public X509CRL genCaCRL(PrivateKey caPrivateKey, X509Certificate x509Certificate, BigInteger certId, int i, String signAlgorithm) throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                new X500Name(x509Certificate.getSubjectDN().getName()),
                new Date()
        );
        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 86400 * 1000));
        // 1 天有效期
        // *被撤销证书序列号*/, new Date() /*被撤销时间*/, 1 /*被撤销原因*/
        crlBuilder.addCRLEntry(certId, new Date(), i);
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signAlgorithm);
        X509CRLHolder crlHolder = crlBuilder.build(contentSignerBuilder.build(caPrivateKey));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        X509CRL crl = converter.getCRL(crlHolder);
        return crl;
    }

    /**
     * 针对旧的crl进行更新
     *
     * @param caPrivateKey
     * @param x509Certificate
     * @param certId
     * @param i
     * @return
     */

    public X509CRL updateCaCRL(X509CRL initialCRL, PrivateKey caPrivateKey, X509Certificate x509Certificate, BigInteger certId, int i) throws Exception {
        X509CRL crl = null;
        //原有crl中的所有的证书序列号及吊销原因
       Set<? extends X509CRLEntry> x509CRLEntries = initialCRL.getRevokedCertificates();

        X509v2CRLBuilder crlBuilder=null;

        for (X509CRLEntry x509CRLEntry : x509CRLEntries) {
            BigInteger id = x509CRLEntry.getSerialNumber();
            crlBuilder = new X509v2CRLBuilder(
                    new X500Name(x509Certificate.getSubjectDN().getName()),
                    x509CRLEntry.getRevocationDate());
            System.out.println("吊销原因取值:"+x509CRLEntry.getRevocationReason().ordinal());
            crlBuilder.addCRLEntry(id, x509CRLEntry.getRevocationDate(), i);
        }

        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 86400 * 1000));
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(initialCRL.getSigAlgName());
        X509CRLHolder crlHolder = crlBuilder.build(contentSignerBuilder.build(caPrivateKey));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        crl = converter.getCRL(crlHolder);
        return crl;
    }


}
