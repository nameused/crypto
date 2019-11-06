package org.crypto.intfs;

import org.crypto.common.exception.SignException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 签名接口
 * @Author: zhangmingyang
 * @Date: 2019/10/25
 * @Company Dingxuan
 */
public interface ISign {

    KeyPair genKeyPair(int keySize) throws SignException;

    /**
     * 数字签名
     * @param data
     * @param privateKey
     * @return
     */
    byte[] sign(byte[] data, PrivateKey privateKey) throws SignException;

    /**
     * 数据验签
     * @param data
     * @param publicKey
     * @param sign
     * @return
     */
    boolean verify(byte[] data, PublicKey publicKey, byte[] sign) throws SignException;
}
