package org.github.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.github.algorithm.gm.sign.SM2;
import org.github.common.utils.FileUtil;
import org.github.intfs.ICert;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class GenCert implements ICert {


    @Override
    public void genGmCert(boolean isCA, String dn, long validData, String dnsName, String rfc822Name) throws Exception {
        System.out.println("=============测试生成国密CA根证书=============");
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.genKeyPair(0);
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        System.out.println("CA PrivateKey:" + Base64.toBase64String(privKey.getEncoded()));

        X500Principal iss = new X500Principal(dn);

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                iss,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + validData * (24 * 60 * 60 * 1000L)),
                iss,
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(0xfe))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, rfc822Name),
                                        new GeneralName(GeneralName.dNSName,dnsName)
                                }));

        // RFC 5280 §4.2.1.9 Basic Contraints:
        // Conforming CAs MUST include this extension in all CA certificates
        // that contain public keys used to validate digital signatures on
        // certificates and MUST mark the extension as critical in such
        // certificates.
        certGen.addExtension(Extension.basicConstraints, isCA, new BasicConstraints(isCA));

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);


        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        cert = (X509Certificate) fact.generateCertificate(bIn);

        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));

        FileUtil.saveFile("CAPrikey", privKey.getEncoded());
        FileUtil.saveFile("CARootCert.cer", cert.getEncoded());
    }

    @Override
    public void genCert(boolean isCA, String algorithm, String  signAlgorithm,String dn, long validData, String dnsName, String rfc822Name) throws Exception {
        System.out.println("=============测试生成国密CA根证书=============");


        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair=keyPairGenerator.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        System.out.println("CA PrivateKey:" + Base64.toBase64String(privKey.getEncoded()));

        X500Principal iss = new X500Principal(dn);

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSA").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                iss,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + validData * (24 * 60 * 60 * 1000L)),
                iss,
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(0xfe))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, rfc822Name),
                                        new GeneralName(GeneralName.dNSName, dnsName)
                                }));

        // RFC 5280 §4.2.1.9 Basic Contraints:
        // Conforming CAs MUST include this extension in all CA certificates
        // that contain public keys used to validate digital signatures on
        // certificates and MUST mark the extension as critical in such
        // certificates.
        certGen.addExtension(Extension.basicConstraints, isCA, new BasicConstraints(isCA));

        X509Certificate cert = new JcaX509CertificateConverter()
               .getCertificate(certGen.build(sigGen));
        cert.checkValidity(new Date());
        cert.verify(pubKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) fact.generateCertificate(bIn);

        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));

        FileUtil.saveFile("CAPrikey", privKey.getEncoded());
        FileUtil.saveFile("CARootCert.cer", cert.getEncoded());
    }

    public static void main(String[] args) throws Exception {
      //  new GenCert().genGmCert(true, "CN=GM ROOT CA,OU=g4b,C=CN,S=Guangdong,O=g4b", 20 * 365, "www.cms-weg.com", "ca.g4b.cn");
        new GenCert().genCert(true,"RSA","sha256withRSA","CN=wlj",20*365,"www.wlj.com","faffaf");
    }
}
