package org.crypto.algorithm.international.hash;

import org.apache.commons.lang3.ArrayUtils;
import org.crypto.common.exception.HashException;
import org.crypto.common.log.CryptoLog;
import org.crypto.common.log.CryptoLogFactory;
import org.crypto.intfs.IHash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
/**
 * @Author: zhangmingyang
 * @Date: 2019/11/21
 * @Company Dingxuan
 */
public class SHA384 implements IHash {
    private static CryptoLog log = CryptoLogFactory.getLog(SHA384.class);
    private static final String ALGORITHM_NAME = "SHA-384";
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
