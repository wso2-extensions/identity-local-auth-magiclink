/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Magic Link";
    public static final String MAGIC_LINK_NOTIFICATION_PAGE = "authenticationendpoint/magic_link_notification.do";
    public static final String MAGIC_LINK_TOKEN = "mlt";
    public static final String EXPIRY_TIME = "ExpiryTime";
    public static final String BLOCKED_USERSTORE_DOMAINS_LIST = "BlockedUserStoreDomains";
    public static final String BLOCKED_USERSTORE_DOMAINS_SEPARATOR = ",";
    public static final String IS_IDF_INITIATED_FROM_MAGIC_LINK_AUTH = "isIdfInitiatedFromMagicLinkAuth";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String IDF_HANDLER_NAME = "IdentifierExecutor";
    public static final String LOCAL = "LOCAL";
    public static final String USER_NAME = "username";
    // Default expiry time in seconds.
    public static final long DEFAULT_EXPIRY_TIME = 300;
    public static final int TOKEN_LENGTH = 32;
    public static final String SKIP_IDENTIFIER_PRE_PROCESS = "skipIdentifierPreProcess";
    public static final String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    public static final String VALIDATE_USERNAME = "ValidateUsername";


}

