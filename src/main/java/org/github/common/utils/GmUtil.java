/**
 * Copyright DingXuan. All Rights Reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.github.common.utils;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * 国密工具类
 *
 * @author zhangmingyang
 * @Date: 11/22/19
 * @Version 1.0.0
 */
public class GmUtil {
    /**
     * RS长度
     */
    private final static int RS_LEN = 32;
    /**
     * SM2参数
     */
    private static final String KEY_GEN_PARAMETER = "sm2p256v1";
    /**
     * EC参数
     */
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName(KEY_GEN_PARAMETER);
    /**
     * EC域参数
     */
    private static ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(),x9ECParameters.getH());
    /**
     * EC域spec
     */
    private static ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
    /**
     * 非压缩性公钥头部
     */
    private static final int HEAD_PUBLIC_KEY_UNCOMPRESSED = 0x04;

    public static byte[] bigIntToFixexLengthBytes(BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // r and s are the result of mod n, so they should be less than n and have length<=32
        byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) {
            return rs;
        } else if (rs.length == RS_LEN + 1 && rs[0] == 0) {
            return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        } else if (rs.length < RS_LEN) {
            byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("err rs: " + Hex.toHexString(rs));
        }
    }

    /**
     * BC的SM3withSM2签名得到的结果的rs是asn1格式的，这个方法转化成直接拼接r||s
     *
     * @param rsDer rs in asn1 format
     * @return sign result in plain byte array
     */
    public static byte[] rsAsn1ToPlainByteArray(byte[] rsDer) {
        ASN1Sequence seq = ASN1Sequence.getInstance(rsDer);
        byte[] r = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    /**
     * BC的SM3withSM2验签需要的rs是asn1格式的，这个方法将直接拼接r||s的字节数组转化成asn1格式
     *
     * @param sign in plain byte array
     * @return rs result in asn1 format
     */
    public static byte[] rsPlainByteArrayToAsn1(byte[] sign) {
        if (sign.length != RS_LEN * 2) {
            throw new RuntimeException("err rs. ");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 由私钥字节数组转换为
     * PrivateKey对象
     *
     * @param sk
     * @return
     */
    public static PrivateKey byteArrayToPrivateKey(byte[] sk) {
        BigInteger d = GmUtil.byteToBigInteger(sk);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, GmUtil.ecParameterSpec);
        PrivateKey privateKey = new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
        return privateKey;
    }


    /**
     * 公钥字节数组转换
     * 为PublicKey对象
     *
     * @return
     */
    public static PublicKey byteArrayToPublickey(byte[] pk){
        Map<String,BigInteger> bigIntegerMap=getXYCode(pk);
        BigInteger x=bigIntegerMap.get("x");
        BigInteger y=bigIntegerMap.get("y");
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecDomainParameters.getCurve().createPoint(x, y), ecParameterSpec);
        ECPublicKey publicKey = new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
        return publicKey;
    }

    /**
     * 字节数组转换大整型
     *
     * @param data
     * @return
     */
    public static BigInteger byteToBigInteger(byte[] data) {
        if (data[0] < 0) {
            byte[] temp = new byte[data.length + 1];
            temp[0] = 0;
            System.arraycopy(data, 0, temp, 1, data.length);
            return new BigInteger(temp);
        }
        return new BigInteger(data);
    }

    /**
     * 将公钥转换为X,Y
     * @param bytes
     * @return
     * @throws CryptoException
     */
    public static Map<String, BigInteger> getXYCode(byte[] bytes) {
        Map<String, BigInteger> map = new HashMap<>();
        if (bytes[0] != HEAD_PUBLIC_KEY_UNCOMPRESSED) {
            throw new RuntimeException("This publicKey not uncompressed");
        }
        int xLength = (bytes.length - 1) / 2;
        byte[] bytesX = new byte[xLength];
        byte[] bytesY = new byte[xLength];
        System.arraycopy(bytes, 1, bytesX, 0, xLength);
        System.arraycopy(bytes, 1 + xLength, bytesY, 0, xLength);
        BigInteger x = byteToBigInteger(bytesX);
        BigInteger y = byteToBigInteger(bytesY);
        map.put("x", x);
        map.put("y", y);
        return map;
    }

    /**
     * 大整形转换字节数组
     * @param temp
     * @return
     */
    public static byte[] BigIntegertoByteArray(BigInteger temp){
        byte[] array = temp.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }

}
