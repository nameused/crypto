/**
 * Copyright Dingxuan. All Rights Reserved.
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

package org.github.algorithm.international.sign;

import org.github.common.exception.SignException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.intfs.ISign;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA签名算法实现
 *
 * @Author: zhangmingyang
 * @Date: 2019/10/25
 * @Company Dingxuan
 */
public class RSA implements ISign {
    private static CryptoLog log = CryptoLogFactory.getLog(RSA.class);
    private static final String KEY_ALGORITHM = "RSA";


    @Override
    public KeyPair genKeyPair(int keySize) throws SignException {
        KeyPairGenerator keyPairGenerator;
        KeyPair keyPair;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(keySize);
            keyPair = keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }

        return keyPair;
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey, String signatureAlgorithm) throws SignException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        Signature signature;
        byte[] signValue;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(priKey);
            signature.update(data);
            signValue = signature.sign();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return signValue;
    }

    @Override
    public boolean verify(byte[] data, PublicKey publicKey, byte[] sign, String signatureAlgorithm) throws SignException {
        boolean verify;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(pubKey);
            signature.update(data);
            verify = signature.verify(sign);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return verify;
    }

    /**
     * 公钥加密
     *
     * @param originalText
     * @param key
     * @return
     */
    public byte[] encryptByPublicKey(byte[] originalText, byte[] key) throws SignException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        Cipher cipher = null;
        byte[] encryptData = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptData = cipher.doFinal(originalText);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return encryptData;
    }

    /**
     * 私钥解密
     *
     * @param encryptText
     * @param key
     * @return
     */
    public byte[] decryptByPrivateKey(byte[] encryptText, byte[] key) throws SignException {
        byte[] encryptData = null;
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            encryptData = cipher.doFinal(encryptText);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return encryptData;
    }
}
