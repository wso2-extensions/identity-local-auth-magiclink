/**
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.magiclink.util;

/**
 * Authentication error constants of MagicLink Authenticator.
 */
public class MagicLinkAuthErrorConstants {

    /**
     * Relevant error messages and error codes.
     * These error codes are commented as a group not because of the convention
     * but to maintain the togetherness of the errors.
     */
    public enum ErrorMessages {

        // Identifier related Error codes.
        EMPTY_USERNAME("BAS-60002", "Username is empty."),

        // IO related Error codes.
        SYSTEM_ERROR_WHILE_AUTHENTICATING("BAS-65001", "System error while authenticating"),
        ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE("BAS-65014",
                "Error occurred while redirecting to the error page"),

        //Account locked error code.
        ERROR_USER_ACCOUNT_LOCKED("BAS-65002", "Account is locked for the user: %s"),
        ERROR_GETTING_ACCOUNT_LOCKED_STATE("BAS-65018", "Error occurred while checking the " +
                "account locked state for the user: %s");


        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s - %s", code, message);
        }
    }
}
