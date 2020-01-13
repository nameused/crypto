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

package org.github.algorithm.international.hash;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.common.exception.HashException;
import org.github.common.log.CryptoLog;
import org.github.common.log.CryptoLogFactory;
import org.github.intfs.IHash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * RipeMD160 实现
 *
 * @Author: zhangmingyang
 * @Date: 2019/12/7
 * @Company Dingxuan
 */
public class RipeMD160 implements IHash {
    private static CryptoLog log = CryptoLogFactory.getLog(RipeMD160.class);
    private static final String ALGORITHM_NAME = "RipeMD160";

    @Override
    public byte[] hash(byte[] data) throws HashException {
        MessageDigest messageDigest = null;
        Security.addProvider(new BouncyCastleProvider());
        try {
            messageDigest = MessageDigest.getInstance(ALGORITHM_NAME);

        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new HashException(e.getMessage(), e);
        }
        return messageDigest.digest(data);
    }
}
