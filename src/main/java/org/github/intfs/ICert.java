package org.github.intfs;


import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * @Author: zhangmingyang
 * @Date: 2021/2/5
 */
public interface ICert {
    /**
     * 生成国密证书
     *
     * @param dn
     * @param validData
     * @param dnsName
     * @param rfc822Name
     * @return
     * @throws Exception
     */
    X509Certificate genGmCaRootCert(KeyPair keyPair, String dn, int validData, String dnsName, String rfc822Name) throws Exception;

    /**
     * 生成非国密证书
     *
     * @param isCA          是否为CA
     * @param signAlgorithm 签名算法
     * @param dn            DN名称
     * @param validData     有效时间,单位为天
     * @param dnsName       dns名称
     * @param rfc822Name    rfcrfc822名称
     * @throws Exception
     */
    X509Certificate genStandardCaRootCert(boolean isCA, KeyPair keyPair, String  signAlgorithm, String dn, int validData, String dnsName, String rfc822Name) throws Exception;


}
