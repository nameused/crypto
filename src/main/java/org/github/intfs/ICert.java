package org.github.intfs;

/**
 * @Author: zhangmingyang
 * @Date: 2021/2/5
 */
public interface ICert {
    /**
     * 生产国密证书
     *
     * @return
     * @throws Exception
     */
    void genGmCert(boolean isCA, String dn, long validData, String dnsName, String rfc822Name) throws Exception;

    /**
     * 生成非国密证书
     *
     * @param isCA       是否为CA
     * @param algorithm  密钥生成算法类型
     * @param signAlgorithm  签名算法
     * @param dn         DN名称
     * @param validData  有效时间,单位为天
     * @param dnsName    dns名称
     * @param rfc822Name rfcrfc822名称
     * @throws Exception
     */
    void genCert(boolean isCA, String algorithm, String signAlgorithm, String dn, long validData, String dnsName, String rfc822Name) throws Exception;


}
