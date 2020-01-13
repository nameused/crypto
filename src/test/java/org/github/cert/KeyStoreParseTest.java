package org.github.cert;

import org.bouncycastle.util.encoders.Base64;
import org.github.common.exception.CertException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * @author zhangmingyang
 * @Date: 2020/1/2
 * @company Dingxuan
 */
public class KeyStoreParseTest {
    KeyStoreParse keyStoreParse;
    KeyStore keyStore;
    private static final String P12_KEYSTROE_PATH = "test-cert/administrator.p12";
    private static final String P12_KEYSTROE_PASSWORD = "szca1234";
    private static final String JKS_KEYSTROE_PATH = "test-cert/truststore.jks";
    private static final String JKS_KEYSTROE_PASSWORD = "123456";


    @Before
    public void setup() throws CertException {
        keyStoreParse = new KeyStoreParse(P12_KEYSTROE_PATH, P12_KEYSTROE_PASSWORD);
        keyStore = keyStoreParse.getKeyStore();
    }

    @Test
    public void getKeyStore() {
        KeyStore keyStore = keyStoreParse.getKeyStore();
        System.out.println(keyStore.getProvider());
    }

    @Test
    public void getPrivateKey() throws CertException {
        PrivateKey privateKey = keyStoreParse.getPrivateKey("bcia administrator", P12_KEYSTROE_PASSWORD);
        String priStr = "-----BEGIN PRIVATE KEY-----\n";
        priStr += new String(Base64.encode(privateKey.getEncoded())) + "\n";
        priStr += "-----END PRIVATE KEY-----";
        System.out.println(priStr);
    }

    @Test
    public void getCertificate() throws KeyStoreException {
        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate("bcia administrator");
        System.out.println(x509Certificate.getSubjectDN());
    }
}