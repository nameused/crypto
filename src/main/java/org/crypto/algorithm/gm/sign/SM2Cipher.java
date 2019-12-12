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
package org.crypto.algorithm.gm.sign;

/**
 * @author zhangmingyang
 * @Date: 2019/12/12
 * @company Dingxuan
 */
public class SM2Cipher {
    /**
     * ECC密钥
     */
    private byte[] c1;

    /**
     * 真正的密文
     */
    private byte[] c2;

    /**
     * 对（c1+c2）的SM3-HASH值
     */
    private byte[] c3;

    /**
     * SM2标准的密文，即（c1+c2+c3）
     */
    private byte[] cipherText;

    public byte[] getC1() {
        return c1;
    }

    public void setC1(byte[] c1) {
        this.c1 = c1;
    }

    public byte[] getC2() {
        return c2;
    }

    public void setC2(byte[] c2) {
        this.c2 = c2;
    }

    public byte[] getC3() {
        return c3;
    }

    public void setC3(byte[] c3) {
        this.c3 = c3;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }
}
