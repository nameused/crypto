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

package org.github.algorithm.international.encryption;

import org.apache.commons.lang3.ArrayUtils;
import org.github.common.exception.EncryptException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.intfs.IEncrypt;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * DES加密算法实现
 *
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class DES implements IEncrypt {

    private static CryptoLog log = CryptoLogFactory.getLog(DES.class);

    private static final String KEY_ALGORITHM = "DES";


    /**
     * 密钥转换
     *
     * @param key
     * @return
     * @throws EncryptException
     */
    private static Key convertKey(byte[] key,String keyAlgorithm) throws EncryptException{
        SecretKey secretKey = null;
        try {
            DESKeySpec desKeySpec = new DESKeySpec(key);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyAlgorithm);
            secretKey = secretKeyFactory.generateSecret(desKeySpec);
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptException(e.getMessage(), e);
        }
        return secretKey;
    }
    /**
     * 密钥初始化
     * <p>
     * java 6 支持56位密钥
     * BC 支持64位密钥
     * 替换keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
     * 为如下:
     * Security.addProvider(new BouncyCastleProvider());
     * keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM,"BC");
     * @param keyLength
     * @return
     * @throws EncryptException
     */
    @Override
    public byte[] genKey(int keyLength) throws EncryptException {
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
    public byte[] encrypt(String cipherAlgorithm, byte[] key, byte[] iv, byte[] originalText) throws EncryptException {
        Key secretKey = convertKey(key,KEY_ALGORITHM);
        byte[] encryptData = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            if (ArrayUtils.isEmpty(iv)) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            }
            encryptData = cipher.doFinal(originalText);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return encryptData;
    }

    @Override
    public byte[] decrypt(String cipherAlgorithm, byte[] key, byte[] iv, byte[] encryptText) throws EncryptException {
        Key secretKey = convertKey(key,KEY_ALGORITHM);
        byte[] decryptData = null;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
            if (ArrayUtils.isEmpty(iv)) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            }
            decryptData = cipher.doFinal(encryptText);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return decryptData;
    }
}
