package org.github.cert;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.github.algorithm.gm.sign.SM2;
import org.github.common.utils.CertUtil;
import org.github.common.utils.FileUtil;
import org.github.intfs.ICert;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

public class GenCert implements ICert {


    @Override
    public X509Certificate genGmCert(boolean isCA, String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        System.out.println("=============生成国密CA根证书=============");
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.genKeyPair(0);
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        System.out.println("CA PrivateKey:" + Base64.toBase64String(privKey.getEncoded()));
        X509Certificate cert =  CertUtil.genGmCertHelper(isCA,pubKey,privKey,dn,validData,dnsName,rfc822Name);
        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));
        FileUtil.saveFile("CAPrikey", privKey.getEncoded());
        FileUtil.saveFile("CAGmRootCert.cer", cert.getEncoded());
        return cert;
    }
    @Override
    public X509Certificate genCert(boolean isCA, String algorithmType,int keySize, String  signAlgorithm,String dn, int validData, String dnsName, String rfc822Name) throws Exception {
        System.out.println("=============生成非国密证书=============");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmType);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair=keyPairGenerator.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        X509Certificate cert =  CertUtil.genStandardCertHelper(isCA,signAlgorithm,pubKey,privKey,dn,validData,dnsName,rfc822Name);
        System.out.println("CA PrivateKey:" + Base64.toBase64String(privKey.getEncoded()));
        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));
        FileUtil.saveFile("CAPrikey", privKey.getEncoded());
        FileUtil.saveFile("CARootCert.cer", cert.getEncoded());
        return cert;
    }


    public X509Certificate genGmCertWithCaSign( X509Certificate caRootCert,PrivateKey caPrivateKey,int keySize, String  signAlgorithm,String dn, int validData, String dnsName, String rfc822Name) throws Exception{
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.genKeyPair(0);
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(caPrivateKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                (X509Certificate) caRootCert,
                BigInteger.valueOf(new Random().nextInt()),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 50000),
                new X500Principal("CN=g4bTestCert"),
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, "gmca@g4b.cn"),
                                        new GeneralName(GeneralName.dNSName, "ca.g4b.cn")
                                }));


        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
        return null;
    }

    public static void main(String[] args) throws Exception {
      //  new GenCert().genGmCert(true, "CN=GM ROOT CA,OU=g4b,C=CN,S=Guangdong,O=g4b", 20 * 365, "www.cms-weg.com", "ca.g4b.cn");
        new GenCert().genCert(true,"RSA",2048,"sha256withRSA","CN=wlj",20,"www.wlj.com","faffaf");
      // Date date=Calendar.getInstance().add(Calendar.YEAR,20);
       // System.out.println(DateUtil.getYearAndMonth("2009-01-01",10));
    }
}
