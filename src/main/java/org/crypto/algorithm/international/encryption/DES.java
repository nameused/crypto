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

package org.crypto.algorithm.international.encryption;

import org.crypto.common.exception.EncryptException;
import org.crypto.common.log.CryptoLog;
import org.crypto.common.log.CryptoLogFactory;
import org.crypto.intfs.IEncrypt;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class DES implements IEncrypt {

    private static CryptoLog log = CryptoLogFactory.getLog(DES.class);

    private static final String KEY_ALGORITHM = "DES";

    private static final String CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";

    /**
     * 密钥转换
     *
     * @param key
     * @return
     * @throws EncryptException
     */
    private static Key convertKey(byte[] key) throws EncryptException {
        SecretKey secretKey = null;
        try {
            DESKeySpec desKeySpec = new DESKeySpec(key);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            secretKey = secretKeyFactory.generateSecret(desKeySpec);
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return secretKey;
    }

    /**
     * 密钥初始化
     * <p>
     * java 6 支持56位密钥
     * BC 支持64位密钥
     *
     * @param keyLength
     * @return
     * @throws EncryptException
     */
    public  byte[] genKey(int keyLength) throws EncryptException {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        keyGenerator.init(keyLength);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    @Override
    public byte[] enprypt(byte[] key, byte[] keyIv, byte[] originalText) throws EncryptException {
        Key secretKey = convertKey(key);
        byte[] encryptData = null;
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptData = cipher.doFinal(originalText);
        } catch (InvalidKeyException | NoSuchAlgorithmException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return encryptData;
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] keyIv,byte[] encryptText) throws EncryptException {
        Key secretKey = convertKey(key);
        byte[] decryptData = null;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            decryptData = cipher.doFinal(encryptText);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return decryptData;
    }
}
