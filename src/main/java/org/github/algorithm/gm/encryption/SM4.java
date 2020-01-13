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

package org.github.algorithm.gm.encryption;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.common.exception.EncryptException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.intfs.IEncrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * SM4实现
 *
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class SM4 implements IEncrypt {
    private static CryptoLog log = CryptoLogFactory.getLog(SM4.class);
    private static final String KEY_ALGORITHM = "SM4";

    /**
     * 秘钥生成
     *
     * @return
     * @throws EncryptException
     */
    @Override
    public byte[] genKey(int keyLength) throws EncryptException {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, new BouncyCastleProvider());
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
        byte[] encryptData = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm, new BouncyCastleProvider());
            Key secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
            if (ArrayUtils.isEmpty(iv)) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            }
            encryptData = cipher.doFinal(originalText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                BadPaddingException | InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return encryptData;
    }

    @Override
    public byte[] decrypt(String cipherAlgorithm, byte[] key, byte[] iv, byte[] encryptText) throws EncryptException {
        byte[] encryptData = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm, new BouncyCastleProvider());
            Key secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
            if (ArrayUtils.isEmpty(iv)) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            }
            encryptData = cipher.doFinal(encryptText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                BadPaddingException | InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
            throw new EncryptException(e.getMessage(), e);
        }
        return encryptData;
    }
}
