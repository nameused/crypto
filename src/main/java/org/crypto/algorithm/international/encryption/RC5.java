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
package org.crypto.algorithm.international.encryption;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.crypto.common.exception.EncryptException;
import org.crypto.common.log.CryptoLog;
import org.crypto.common.log.CryptoLogFactory;
import org.crypto.intfs.IEncrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * @author zhangmingyang
 * @Date: 2019/12/31
 * @company Dingxuan
 */
public class RC5 implements IEncrypt {
    private static CryptoLog log = CryptoLogFactory.getLog(RC5.class);

    private static final String KEY_ALGORITHM = "RC5";

    /**
     * 密钥转换
     *
     * @param key
     * @return
     * @throws EncryptException
     */
    private static Key convertKey(byte[] key, String keyAlgorithm) throws EncryptException {
        SecretKey secretKey = new SecretKeySpec(key, keyAlgorithm);
        return secretKey;
    }

    /**
     * 密钥生成
     *
     * @param keyLength
     * @return
     * @throws EncryptException
     */
    @Override
    public byte[] genKey(int keyLength) throws EncryptException {
        KeyGenerator keyGenerator = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
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
        Security.addProvider(new BouncyCastleProvider());
        Key secretKey = convertKey(key, KEY_ALGORITHM);
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
        Security.addProvider(new BouncyCastleProvider());
        Key secretKey = convertKey(key, KEY_ALGORITHM);
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
