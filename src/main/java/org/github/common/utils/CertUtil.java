package org.github.common.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

public class CertUtil {

    /**
     * 生成国密证书辅助方法
     * @param pubKey
     * @param privKey
     * @param dn
     * @param validData
     * @param dnsName
     * @param rfc822Name
     * @return
     * @throws Exception
     */
    public static X509Certificate genGmCertHelper(PublicKey pubKey, PrivateKey privKey, String dn, int validData, String dnsName, String rfc822Name) throws Exception{
        X500Principal iss = new X500Principal(dn);

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                iss,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                CommUtil.getDate(validData), iss, pubKey)
                .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(0xfe))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, rfc822Name),
                                        new GeneralName(GeneralName.dNSName,dnsName)
                                }));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(certGen.build(sigGen));
        cert.checkValidity(new Date());
        cert.verify(pubKey);
        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        cert = (X509Certificate) fact.generateCertificate(bIn);
        return cert;
    }


    /**
     * 利用CA签名生成国密证书
     * @param caRootCert
     * @param caPrivateKey 根ca私钥
     * @param publicKey    用户的公钥
     * @param signAlgorithm
     * @param dn
     * @param validData
     * @param dnsName
     * @param rfc822Name
     * @return
     * @throws Exception
     */
    public static X509Certificate genCertWithCaSign(X509Certificate caRootCert,PrivateKey caPrivateKey,PublicKey publicKey, String  signAlgorithm,String dn, int validData, String dnsName, String rfc822Name) throws Exception {


        if(signAlgorithm.equalsIgnoreCase("SM3withSM2")){
            ContentSigner sigGen = new JcaContentSignerBuilder(signAlgorithm).setProvider("BC").build(caPrivateKey);
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    caRootCert,
                    BigInteger.valueOf(new Random().nextInt()),
                    new Date(System.currentTimeMillis()),
                    CommUtil.getDate(validData),
                    new X500Principal(dn),
                    publicKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                    new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
                    .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                            new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                    .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                            new GeneralNames(new GeneralName[]
                                    {
                                            new GeneralName(GeneralName.rfc822Name, rfc822Name),
                                            new GeneralName(GeneralName.dNSName, dnsName)
                                    }));
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
            return cert;
        }
        ContentSigner sigGen = new JcaContentSignerBuilder(signAlgorithm).build(caPrivateKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                caRootCert,
                BigInteger.valueOf(new Random().nextInt()),
                new Date(System.currentTimeMillis()),
                CommUtil.getDate(validData),
                new X500Principal(dn),
                publicKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, rfc822Name),
                                        new GeneralName(GeneralName.dNSName, dnsName)
                                }));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
        return cert;

    }

    /**
     * 生成非国密证书辅助方法
     * @param isCA
     * @param signAlgorithm
     * @param pubKey
     * @param privKey
     * @param dn
     * @param validData
     * @param dnsName
     * @param rfc822Name
     * @return
     * @throws Exception
     */
    public static X509Certificate genStandardCertHelper(boolean isCA, String  signAlgorithm,PublicKey pubKey, PrivateKey privKey,String dn, int validData, String dnsName, String rfc822Name) throws Exception{
        X500Principal iss = new X500Principal(dn);

        ContentSigner sigGen = new JcaContentSignerBuilder(signAlgorithm).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                iss,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                CommUtil.getDate(validData), iss, pubKey)
                .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                        new X509KeyUsage(0xfe))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, rfc822Name),
                                        new GeneralName(GeneralName.dNSName,dnsName)
                                }));
        certGen.addExtension(Extension.basicConstraints, isCA, new BasicConstraints(isCA));

        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
        cert.checkValidity(new Date());
        cert.verify(pubKey);
        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) fact.generateCertificate(bIn);
        return cert;
    }




}
