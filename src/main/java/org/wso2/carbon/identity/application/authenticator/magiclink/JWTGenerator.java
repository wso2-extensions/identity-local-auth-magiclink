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

@SuppressWarnings("checkstyle:LineLength")
public class JWTGenerator {

    private final JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS256.getName());

    /**
     * @param username       the username of the user
     * @param sessionDataKey the sessionDataKey
     * @param iss            the issuer of token
     * @param aud            the audience of token
     * @param exp            the expiration duration
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
     * @param tenantDomain   tenant domain of the user
     * @param username       username of the user
     * @param sessionDataKey the sessionDataKey
     * @param iss            the issuer of  token
     * @param aud            the audience of token
     * @param exp            the expiration duration
     * @return
     * @throws IdentityOAuth2Exception
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
