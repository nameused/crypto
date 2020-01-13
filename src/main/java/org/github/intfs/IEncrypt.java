package org.github.intfs;

import org.github.common.exception.EncryptException;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public interface IEncrypt {

    /**
     * 密钥生产
     * @param keyLength
     * @return
     * @throws EncryptException
     */
    byte[] genKey(int keyLength) throws EncryptException;
    /**
     *加密
     * @param cipherAlgorithm 加密算法及填充方式
     * @param key
     * @param iv  ecb模式无需传值
     * @param originalText
     * @return
     * @throws EncryptException
     */
    byte[] encrypt(String cipherAlgorithm,byte[] key, byte[] iv, byte[] originalText) throws EncryptException;

    /**
     * 解密
     * @param cipherAlgorithm 加密算法及填充方式
     * @param key
     * @param iv ecb模式无需传值
     * @param encryptText
     * @return
     * @throws EncryptException
     */
    byte[] decrypt(String cipherAlgorithm,byte[] key, byte[] iv, byte[] encryptText) throws EncryptException;
}
