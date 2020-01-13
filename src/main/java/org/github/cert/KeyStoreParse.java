/**
 * Copyright DingXuan. All Rights Reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.github.cert;

import org.github.common.exception.CertException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * 密钥库解析
 *
 * @author zhangmingyang
 * @Date: 2020/1/2
 * @company Dingxuan
 */
public class KeyStoreParse {
    private static CryptoLog log = CryptoLogFactory.getLog(KeyStoreParse.class);
    private String keyStorePath;
    private String password;
    private KeyStore keyStore;

    public KeyStoreParse(String keyStorePath, String password) throws CertException {
        this.keyStorePath = keyStorePath;
        this.password = password;
        this.keyStore = setKeyStore();
    }

    /**
     * 获取密钥库
     *
     * @return
     */
    public KeyStore setKeyStore() throws CertException {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream fileInputStream = new FileInputStream(keyStorePath);
            keyStore.load(fileInputStream, password.toCharArray());
            fileInputStream.close();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e.getMessage());
            throw new CertException(e.getMessage(),e);
        }
        return keyStore;
    }

    /**
     * 获取私钥
     *
     * @param alias
     * @param password
     * @return
     */
    public PrivateKey getPrivateKey(String alias, String password) throws CertException  {
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error(e.getMessage());
            throw new CertException(e.getMessage(),e);
        }
        return privateKey;
    }

    /**
     * 根据key获取证书对象
     * @param alias
     * @return
     */
    public Certificate getCertificate(String alias) throws CertException  {
        Certificate certificate = null;
        try {
            certificate = keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            log.error(e.getMessage());
            e.printStackTrace();
        }
        return certificate;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
    public String getKeyStorePath() {
        return keyStorePath;
    }
    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}
