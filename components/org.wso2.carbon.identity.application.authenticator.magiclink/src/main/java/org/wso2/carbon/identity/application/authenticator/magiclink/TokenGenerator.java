/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.magiclink;

import java.security.SecureRandom;

/**
 * Token Generator related to magic link authentication flow.
 */
public class TokenGenerator {

    private static SecureRandom random = new SecureRandom();
    private static final String CHARACTER_SET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    /**
     * This method will generate a random token.
     *
     * @param length Token length.
     * @return Magic token.
     */
    public static String generateToken(int length) {

        StringBuffer randomString = new StringBuffer(length);
        for (int i = 0; i < length; i++) {
            int offset = random.nextInt(CHARACTER_SET.length());
            randomString.append(CHARACTER_SET.substring(offset, offset + 1));
        }
        return randomString.toString();
    }
}
