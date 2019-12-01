package org.crypto.intfs;

import org.crypto.common.exception.EncryptException;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public interface IEncrypt {
    /**
     * 加密
     *
     * @param key
     * @param keyIv
     * @param originalText
     * @return
     * @throws EncryptException
     */
    byte[] enprypt(byte[] key, byte[] keyIv, byte[] originalText) throws EncryptException;

    /**
     * 解密
     *
     * @param key
     * @param keyIv
     * @param encryptText
     * @return
     * @throws EncryptException
     */
    byte[] decrypt(byte[] key, byte[] keyIv, byte[] encryptText) throws EncryptException;
}
