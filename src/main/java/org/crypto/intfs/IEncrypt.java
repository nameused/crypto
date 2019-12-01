package org.crypto.intfs;

import org.crypto.common.exception.EncryptException;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public interface IEncrypt {
    /**
     * 数据加密
     *
     * @param key
     * @param originalText
     * @return
     */
    byte[] enprypt(byte[] key, byte[] originalText, String encryptMode) throws EncryptException;

    /**
     * 数据解密
     *
     * @param key
     * @param encryptText
     * @param encryptMode
     * @return
     */
    byte[] decrypt(byte[] key, byte[] encryptText, String encryptMode) throws EncryptException;
}
