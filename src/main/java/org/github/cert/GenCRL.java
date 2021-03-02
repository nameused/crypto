package org.github.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.github.common.utils.GmUtil;

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
        //unspecified	未指定
        //keyCompromise	私钥泄漏
        //cACompromise	CA 私钥可能泄漏
        //affiliationChanged	组织变化，隶属关系变更
        //superseded	被取代
        //cessationOfOperation	CA 停用
        //certificateHold	临时吊销
        //removeFromCRL	使用 certificateHold 吊销的证书，可以用 removeFromCRL 取消吊销
        //privilegeWithdrawn	因证书某权限被撤销而吊销
        //aACompromise	indicates that it is known or suspected that aspects of the AA validated in the attribute certificate have been compromised
       // BigInteger bigIntCertId=GmUtil.byteToBigInteger(Hex.decode(certId));
        crlBuilder.addCRLEntry(certId, new Date(), i);
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signAlgorithm);
        //contentSignerBuilder.setProvider("BC");
        X509CRLHolder crlHolder = crlBuilder.build(contentSignerBuilder.build(caPrivateKey));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        //converter.setProvider("BC");
        X509CRL crl = converter.getCRL(crlHolder);
        return crl;
    }


}
