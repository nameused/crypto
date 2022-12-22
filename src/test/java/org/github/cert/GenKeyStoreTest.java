package org.github.cert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class GenKeyStoreTest {
    @Test
    public void genKeyStore() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        GenKeyStore.genKeyStore("D:\\code\\java-code\\crypto\\StandardUserCert.pem", "D:\\code\\java-code\\crypto\\StandardUserPrivateKey.pem ", "123456");
        //  GenKeyStore.genGmKeyStore("D:\\code\\java-code\\crypto\\GmCARootCert.pem", "D:\\code\\java-code\\crypto\\GmCAPrikey.pem", "111111");
    }

}
