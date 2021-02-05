package org.github.intfs;

/**
 * @Author: zhangmingyang
 * @Date: 2021/2/5
 */
public interface ICert {
    /**
     * @return
     * @throws Exception
     */
    String generateCert(boolean isCA) throws Exception;
}
