/**
 * Copyright Dingxuan. All Rights Reserved.
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

package org.crypto.sign.international;

import org.crypto.common.exception.SignException;
import org.crypto.common.log.CryptoLog;
import org.crypto.common.log.CryptoLogFactory;
import org.crypto.intfs.ISign;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * DSA 签名算法实现
 *
 * @Author: zhangmingyang
 * @Date: 2019/10/25
 * @Company Dingxuan
 */
public class DSA implements ISign {
    private static final String KEY_ALGORITHM = "DSA";
    private static final String SIGNATURE_ALGORITHM = "SHA1WithDSA";
    private static CryptoLog log = CryptoLogFactory.getLog(DSA.class);

    @Override
    public KeyPair genKeyPair(int keySize) throws SignException {
        KeyPairGenerator keyPairGenerator;
        KeyPair keyPair;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(keySize);
            keyPair = keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return keyPair;
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) throws SignException {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        Signature signature;
        byte[] signValue;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(priKey);
            signature.update(data);
            signValue = signature.sign();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return signValue;
    }

    @Override
    public boolean verify(byte[] data, PublicKey publicKey, byte[] sign) throws SignException {
        boolean verify;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(pubKey);
            signature.update(data);
            verify = signature.verify(sign);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error(e.getMessage());
            throw new SignException(e.getMessage(), e);
        }
        return verify;
    }
}
