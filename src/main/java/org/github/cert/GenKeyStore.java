package org.github.cert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.common.utils.CryptoUtil;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class GenKeyStore {

    /**
     * 生成非国密的JKS格式密钥库
     * 根据生成的证书与私钥构建JKS格式的密钥库;
     * 可用于服务端进行SSL证书配置
     *
     * @param certPath
     * @param privateKeyPath
     * @param passwrod
     * @throws Exception
     */
    public static void genKeyStore(String certPath, String privateKeyPath, String passwrod) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = CryptoUtil.parseKeyPairFromPem(privateKeyPath);
        FileOutputStream stream = new FileOutputStream("tomcat.pfx");
        PrivateKey privateKey = keyPair.getPrivate();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream(certPath));
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, passwrod.toCharArray());
        keyStore.setCertificateEntry("tomcat", certificate);
        keyStore.setKeyEntry("tomcat", privateKey, passwrod.toCharArray(), new Certificate[]{certificate});
        keyStore.store(stream, passwrod.toCharArray());
        stream.close();
    }


    /**
     * 生成国密格式的JKS
     *
     * @param certPath
     * @param privateKeyPath
     * @param passwrod
     * @throws Exception
     */
    public static void genGmKeyStore(String certPath, String privateKeyPath, String passwrod) throws Exception {
        KeyPair keyPair = CryptoUtil.parseKeyPairFromPem(privateKeyPath);
        FileOutputStream stream = new FileOutputStream("tomcat.pfx");
        PrivateKey privateKey = keyPair.getPrivate();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream(certPath));
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, passwrod.toCharArray());
        keyStore.setCertificateEntry("tomcat", certificate);
        keyStore.setKeyEntry("tomcat", privateKey, passwrod.toCharArray(), new Certificate[]{certificate});
        keyStore.store(stream, passwrod.toCharArray());
        stream.close();
    }


}
