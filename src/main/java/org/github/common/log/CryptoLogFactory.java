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

package org.github.common.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 日志工厂
 * @Author: zhangmingyang
 * @Date: 2019/10/25
 * @Company Dingxuan
 */
public class CryptoLogFactory {
    public static CryptoLog getLog(Class<?> clazz) {
        Logger logger = LoggerFactory.getLogger(clazz);

        CryptoLog log = new CryptoLog();
        log.setLogger(logger);
        return log;
    }

    public static CryptoLog getLog(String name) {
        Logger logger = LoggerFactory.getLogger(name);

        CryptoLog log = new CryptoLog();
        log.setLogger(logger);
        return log;
    }

    public static CryptoLog getLog() {
        StackTraceElement[] sts = Thread.currentThread().getStackTrace();
        Logger logger = LoggerFactory.getLogger(sts[2].getClassName());

        CryptoLog log = new CryptoLog();
        log.setLogger(logger);
        return log;
    }
}
