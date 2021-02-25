package org.github.common.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Enumeration;

/**
 * 加密常用工具类
 */
public class CryptoUtil {

    public static String parseAsn1Data(byte[] data) throws IOException {
        ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(data));
        ASN1Primitive obj = bIn.readObject();
        System.out.println(ASN1Dump.dumpAsString(obj));
        return ASN1Dump.dumpAsString(obj);
    }



    /**
     * 支持将证书、秘钥转换为可写入pem文件的base64格式
     * @param certificate
     * @return
     * @throws Exception
     */
    public static String convertBase64Pem(Object certificate) throws Exception{
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }
        return sw.toString();
    }

}
