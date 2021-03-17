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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Objects;

/**
 * JWT validator related to magic link authentication flow.
 */
public class JWTValidator {

    private static final String DOT_SEPARATOR = ".";

    public static boolean validate(String magicToken, String tenantDomain)
            throws IdentityOAuth2Exception {

        if (!isJWT(magicToken)) {
            return false;
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(magicToken);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given code.");
            }
            if (!validateSignature(tenantDomain, signedJWT)) {
                return false;
            }
            if (!checkExpirationTime(claimsSet.getExpirationTime())) {
                return false;
            }
            if (!checkNotBeforeTime(claimsSet.getNotBeforeTime())) {
                return false;
            }
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating magicToken", e);
        }
        return true;
    }

    public static JWTClaimsSet getClaimSet(String magicToken) {

        try {
            SignedJWT signedJWT = SignedJWT.parse(magicToken);
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Method used in Magic Link Authenticator class to get the username in JWT.
     *
     * @param magicToken The magicToken in the link.
     * @return
     */
    public static String getUsername(String magicToken) {

        return Objects.requireNonNull(JWTValidator.getClaimSet(magicToken)).getSubject();
    }

    /**
     * Method used in Magic Link authenticator class to get the sessionDataKey in the JWT.
     *
     * @param magicToken The magicToken in the link.
     * @return
     */
    public static String getSessionDataKey(String magicToken) {

        return Objects.requireNonNull(JWTValidator.getClaimSet(magicToken)).getJWTID();
    }

    public static boolean validateSignature(String tenantDomain, SignedJWT signedJWT) {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            RSAPublicKey publicKey;
            if (!tenantDomain.equals("carbon.super")) {
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(jksName).getCertificate(tenantDomain)
                        .getPublicKey();
            } else {
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            return signedJWT.verify(verifier);
        } catch (Exception var10) {
            return false;
        }
    }

    private static boolean checkExpirationTime(Date expirationTime) {

        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();
        return (currentTimeInMillis + timeStampSkewMillis) <= expirationTimeInMillis;
    }

    private static boolean checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
        }
        return true;
    }

    /**
     * Return true if the token identifier is JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    private static boolean isJWT(String tokenIdentifier) {

        return StringUtils.countMatches(tokenIdentifier, DOT_SEPARATOR) == 2;
    }

}
