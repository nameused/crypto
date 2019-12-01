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

package org.crypto.algorithm.international.encryption;

import org.crypto.common.exception.EncryptException;
import org.crypto.intfs.IEncrypt;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * @Author: zhangmingyang
 * @Date: 2019/11/19
 * @Company Dingxuan
 */
public class DES implements IEncrypt {
    @Override
    public byte[] enprypt(byte[] key, byte[] originalText, String encryptMode) throws EncryptException {
        SecureRandom secureRandom = new SecureRandom();
        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = null;
        Cipher cipher = null;
        byte[] encryptData = null;
        try {
            dks = new DESKeySpec(key);
            // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
            SecretKeyFactory keyFactory = null;
            keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = null;
            securekey = keyFactory.generateSecret(dks);
            // Cipher对象实际完成加密操作
            cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, securekey, secureRandom);
            encryptData = cipher.doFinal(originalText);
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptData;
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] encryptText, String encryptMode) throws EncryptException {
        return new byte[0];
    }
}
