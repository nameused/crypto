package org.github.common.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

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

    public static void main(String[] args) throws IOException {
        CryptoUtil.parseAsn1Data(Hex.decode("308188020100301306072a8648ce3d020106082a811ccf5501822d046e306c02010102210086ab9d392e8af3a647529922" +
                "38ec8670255b763796f9bbd9a4f63a235f8262b9a144034200049140b21201150bf095253d64e8279b6d3888eb2461e71cc28f2a07436eec83355084813f6933454985d779bbac880ddded31943976ccced875dd954a5975ac2c"));
    }

}
