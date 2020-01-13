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

package org.github.algorithm.gm.hash;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.common.exception.HashException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.intfs.IHash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * SM3 实现
 *
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class SM3 implements IHash {
    private static CryptoLog log = CryptoLogFactory.getLog(SM3.class);

    @Override
    public byte[] hash(byte[] data) throws HashException {
        if (ArrayUtils.isEmpty(data)) {
            throw new HashException("Some input is empty");
        }
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("sm3");
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new HashException(e);
        }
        messageDigest.update(data);
        return messageDigest.digest();
    }
}
