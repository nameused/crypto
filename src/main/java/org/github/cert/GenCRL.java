package org.github.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

public class GenCRL {

    /**
     * 生成CA的CRL列表
     *
     * @param caPrivateKey
     * @param x509Certificate
     * @return
     * @throws Exception
     */
    public X509CRL genCaCRL(PrivateKey caPrivateKey, X509Certificate x509Certificate,BigInteger certId,int i,String signAlgorithm) throws Exception {
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


}
