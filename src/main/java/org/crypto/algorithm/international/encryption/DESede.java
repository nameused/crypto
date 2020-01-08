package org.crypto.algorithm.international.encryption;

import org.apache.commons.lang3.ArrayUtils;
import org.crypto.common.exception.EncryptException;
import org.crypto.common.log.CryptoLog;
import org.crypto.common.log.CryptoLogFactory;
import org.crypto.intfs.IEncrypt;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * DESede算法实现，及3DES算法
 *
 * @Author: zhangmingyang
 * @Date: 2019/12/9
 * @Company Dingxuan
 */
public class DESede implements IEncrypt {
    private static CryptoLog log = CryptoLogFactory.getLog(DES.class);
    private static final String KEY_ALGORITHM = "DESede";


    /**
     * 密钥转换
     *
     * @param key
     * @return
     * @throws EncryptException
     */
    private static Key convertKey(byte[] key, String keyAlgorithm) throws EncryptException {
        SecretKey secretKey = null;
        try {
            DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyAlgorithm);
            secretKey = secretKeyFactory.generateSecret(desKeySpec);
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptException(e.getMessage(), e);
        }
        return secretKey;
    }

    @Override
    public byte[] genKey(int keyLength) throws EncryptException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(keyLength);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new EncryptException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] encrypt(String cipherAlgorithm, byte[] key, byte[] iv, byte[] originalText) throws EncryptException {
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
