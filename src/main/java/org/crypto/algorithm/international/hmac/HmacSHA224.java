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

package org.crypto.algorithm.international.hmac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.crypto.common.exception.HmacException;
import org.crypto.common.log.CryptoLog;
import org.crypto.common.log.CryptoLogFactory;
import org.crypto.intfs.IHmac;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @Author: zhangmingyang
 * @Date: 2019/12/8
 * @Company Dingxuan
 */
public class HmacSHA224 implements IHmac {
    private static CryptoLog log = CryptoLogFactory.getLog(HmacSHA224.class);
    private static final String ALGORITHM_NAME = "HmacSHA224";

    @Override
    public byte[] initKey() throws HmacException {
        SecretKey secretKey = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_NAME);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new HmacException(e.getMessage(), e);
        }
        return secretKey.getEncoded();
    }

    @Override
    public byte[] hmac(byte[] data, byte[] key) throws HmacException {
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM_NAME);
        Mac mac = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error(e.getMessage());
            throw new HmacException(e.getMessage(), e);
        }
        return mac.doFinal(data);
    }
}
