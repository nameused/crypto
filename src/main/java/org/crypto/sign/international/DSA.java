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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * DSA 签名算法实现
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
        return null;
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) throws SignException {
        return new byte[0];
    }

    @Override
    public boolean verify(byte[] data, PublicKey publicKey, byte[] sign) throws SignException {
        return false;
    }
}
