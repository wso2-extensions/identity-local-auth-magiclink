/**
 * Copyright (c) 2021, WSO2 LLC. (https://www.wso2.com).
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
package org.wso2.carbon.identity.application.authenticator.magiclink;

/**
 * Constants related to magic link authentication flow.
 */
public abstract class MagicLinkAuthenticatorConstants {

    /**
     * Private Constructor will prevent the instantiation of this class directly.
     */
    private MagicLinkAuthenticatorConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "MagicLinkAuthenticator";
    public static final String AUTHENTICATOR_MAGIC_LINK = "authenticator.magic.link";
    public static final String MLT = "mlt";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Magic Link";
    public static final String MAGIC_LINK_NOTIFICATION_PAGE = "authenticationendpoint/magic_link_notification.do";
    public static final String MAGIC_LINK_AUTHENTICATION_ENDPOINT_URL = "MagicLinkAuthenticationEndpointURL";
    public static final String MAGIC_LINK_TOKEN = "mlt";
    public static final String DISPLAY_MAGIC_LINK_TOKEN = "Magic Link Token";
    public static final String EXPIRY_TIME = "ExpiryTime";
    public static final String BLOCKED_USERSTORE_DOMAINS_LIST = "BlockedUserStoreDomains";
    public static final String BLOCKED_USERSTORE_DOMAINS_SEPARATOR = ",";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String IS_IDF_INITIATED_FROM_AUTHENTICATOR = "isIdfInitiatedFromAuthenticator";
    public static final String IDF_HANDLER_NAME = "IdentifierExecutor";
    public static final String LOCAL = "LOCAL";
    public static final String USER_NAME = "username";
    public static final String DISPLAY_USER_NAME = "Username";
    public static final String USERNAME_PARAM = "username.param";
    public static final String MAGIC_LINK_CODE = "magic.link.code.param";
    public static final String USER_PROMPT = "USER_PROMPT";

    // Default expiry time in seconds.
    public static final long DEFAULT_EXPIRY_TIME = 300;
    public static final int TOKEN_LENGTH = 32;
    public static final String MAGIC_TOKEN = "magicToken";
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String EVENT_NAME = "magicLink";
    public static final String EXPIRYTIME = "expiry-time";
    public static final String IS_API_BASED_AUTHENTICATION_SUPPORTED = "isAPIBasedAuthenticationSupported";
    public static final String CALLBACK_URL = "callbackUrl";
    public static final String STATE_PARAM_SUFFIX = "_state_param";
    public static final String STATE_PARAM = "state";
    public static final String MULTI_OPTION_QUERY_PARAM = "multiOptionURI";

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String MAGIC_LINK_AUTH_SERVICE = "local-auth-magiclink";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String SEND_MAGIC_LINK = "send-magiclink-token";
            public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-authentication-response";
            public static final String VALIDATE_MAGIC_LINK_REQUEST = "validate-authentication-request";
        }
    }
}

