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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Calendar;
import java.util.Date;

/**
 * JWT Generator related to magic link authentication flow.
 */
public class JWTGenerator {

    /**
     * JWSAlgorithm used to sign JWT.
     */
    private final JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS256.getName());

    /**
     * This method is used to create JWT claim set.
     *
     * @param username       The username of the user.
     * @param sessionDataKey The sessionDataKey.
     * @param iss            The issuer of token.
     * @param aud            The audience of token.
     * @param exp            The expiration duration.
     * @return
     */
    protected JWTClaimsSet createJWTClaimSet(String username, String sessionDataKey, String iss, String aud,
                                             String exp) {

        long currentTime = Calendar.getInstance().getTimeInMillis();
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(username);
        claimsSetBuilder.issueTime(new Date(currentTime));
        long validityPeriodInMillis = Long.parseLong(exp);
        long expireIn = validityPeriodInMillis + currentTime;
        claimsSetBuilder.expirationTime(new Date(expireIn));
        claimsSetBuilder.notBeforeTime(new Date(currentTime));
        claimsSetBuilder.jwtID(sessionDataKey);
        claimsSetBuilder.issuer(iss);
        claimsSetBuilder.audience(aud);
        return claimsSetBuilder.build();
    }

    /**
     * This method is used to generate JWT signed token.
     *
     * @param tenantDomain   Tenant domain of the user.
     * @param username       Username of the user.
     * @param sessionDataKey The sessionDataKey.
     * @param iss            The issuer of  token.
     * @param aud            The audience of token.
     * @param exp            The expiration duration.
     * @return
     * @throws IdentityOAuth2Exception In occasions of failing to generate JWT.
     */
    protected JWT generateToken(String tenantDomain, String username, String sessionDataKey, String iss, String aud,
                                String exp) throws
            IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = this.createJWTClaimSet(username, sessionDataKey, iss, aud, exp);
        JWT jwt;
        if (!JWSAlgorithm.NONE.equals(signatureAlgorithm)) {
            jwt = OAuth2Util.signJWTWithRSA(claimsSet, signatureAlgorithm, tenantDomain);
        } else {
            jwt = new PlainJWT(claimsSet);
        }
        return jwt;
    }
}



