package org.github.algorithm.international.hash;

import org.apache.commons.lang3.ArrayUtils;
import org.github.common.exception.HashException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.intfs.IHash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/21
 * @Company Dingxuan
 */
public class SHA512 implements IHash {
    private static CryptoLog log = CryptoLogFactory.getLog(SHA512.class);
    private static final String ALGORITHM_NAME = "SHA-512";
    @Override
    public byte[] hash(byte[] data) throws HashException {
        if (ArrayUtils.isEmpty(data)) {
            throw new HashException("Some input is empty");
        }
        MessageDigest messageDigest= null;
        try {
            messageDigest = MessageDigest.getInstance(ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(),e);
            throw new HashException(e);
        }
        return messageDigest.digest(data);
    }
}
