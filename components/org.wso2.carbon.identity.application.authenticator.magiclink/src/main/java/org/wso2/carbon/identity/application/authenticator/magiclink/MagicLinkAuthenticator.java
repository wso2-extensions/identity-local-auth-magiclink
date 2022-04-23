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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCache;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheEntry;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheKey;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.DEFAULT_EXPIRY_TIME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.EXPIRY_TIME;

/**
 * Authenticator of MagicLink.
 */
public class MagicLinkAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(MagicLinkAuthenticator.class);

    /**
     * This method is used initiate authenticate request.
     *
     * @param request  The httpServletRequest.
     * @param response The httpServletResponse.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException In occasions of failing to send the magicToken to the user.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        User user = getUser(context.getLastAuthenticatedUser());
        if (user != null) {
            MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
            String magicToken = TokenGenerator.generateToken(MagicLinkAuthenticatorConstants.TOKEN_LENGTH);
            magicLinkAuthContextData.setMagicToken(magicToken);
            magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis());
            magicLinkAuthContextData.setUser(user);
            magicLinkAuthContextData.setSessionDataKey(context.getContextIdentifier());

            MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(magicToken);
            MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);
            MagicLinkAuthContextCache.getInstance().addToCache(cacheKey, cacheEntry);

            if (StringUtils.isNotEmpty(magicToken)) {
                triggerEvent(user.getUsername(), user.getUserStoreDomain(), user.getTenantDomain(), magicToken);
            }
        }
        try {
            String url = ServiceURLBuilder.create()
                    .addPath(MagicLinkAuthenticatorConstants.MAGIC_LINK_NOTIFICATION_PAGE).build()
                    .getAbsolutePublicURL();
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting to the magic link notification page.", e);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error while building the magic link notification page URL.", e);
        }
    }

    /**
     * This method is used to process the authentication response.
     *
     * @param request  The httpServletRequest.
     * @param response The httpServletResponse.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException In occasions of failing to validate magicToken.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        if (StringUtils.isEmpty(request.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN))) {
            throw new InvalidCredentialsException("MagicToken cannot be null.");
        } else {
            String magicToken = request.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN);
            MagicLinkAuthContextCacheKey magicLinkAuthContextCacheKey = new MagicLinkAuthContextCacheKey(magicToken);
            MagicLinkAuthContextCacheEntry magicLinkAuthContextCacheEntry = MagicLinkAuthContextCache.getInstance()
                    .getValueFromCache(magicLinkAuthContextCacheKey);

            if (isMagicTokenValid(magicLinkAuthContextCacheEntry)) {
                MagicLinkAuthContextData magicLinkAuthContextData =
                        magicLinkAuthContextCacheEntry.getMagicLinkAuthContextData();
                UserCoreUtil.setDomainInThreadLocal(magicLinkAuthContextData.getUser().getUserStoreDomain());
                AuthenticatedUser authenticatedUser =
                        AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                        magicLinkAuthContextData.getUser().getFullQualifiedUsername());
                context.setSubject(authenticatedUser);
                MagicLinkAuthContextCache.getInstance().clearCacheEntry(magicLinkAuthContextCacheKey);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Given MagicToken is not valid.");
                }
                throw new InvalidCredentialsException("MagicToken is not valid.");
            }
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {

        return MagicLinkAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        return StringUtils.isNotEmpty(
                httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String magicToken = request.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN);

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(magicToken);
        MagicLinkAuthContextCacheEntry cacheEntry = MagicLinkAuthContextCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry != null) {
            return cacheEntry.getMagicLinkAuthContextData().getSessionDataKey();
        }
        return null;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {

        return MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Method to Trigger the Magic Link event.
     *
     * @param username        The username of the user.
     * @param userStoreDomain The serStoreDomain of the user.
     * @param tenantDomain    The tenantDomain of the user.
     * @param magicToken      The magicToken sent to email.
     * @throws AuthenticationFailedException In occasions of failing to send the email to the user.
     */
    protected void triggerEvent(String username, String userStoreDomain, String tenantDomain, String magicToken)
            throws AuthenticationFailedException {

        String eventName = "TRIGGER_NOTIFICATION";
        HashMap<String, Object> properties = new HashMap();
        properties.put("user-name", username);
        properties.put("userstore-domain", userStoreDomain);
        properties.put("tenant-domain", tenantDomain);
        properties.put("magicToken", magicToken);
        properties.put("TEMPLATE_TYPE", "magicLink");
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            MagicLinkServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = String.format(
                    "Error occurred while sending the notification for the user: %s in the tenant: %s", username,
                    tenantDomain);
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    private boolean isMagicTokenValid(MagicLinkAuthContextCacheEntry cacheEntry) {

        if (cacheEntry != null) {
            long currentTimestamp = System.currentTimeMillis();
            long createdTimestamp = cacheEntry.getMagicLinkAuthContextData().getCreatedTimestamp();
            long tokenValidityPeriod = TimeUnit.SECONDS.toMillis(getExpiryTime());
            // Validate whether the token is expired.
            if (currentTimestamp - createdTimestamp < tokenValidityPeriod) {
                return true;
            }
        }
        return false;
    }

    private long getExpiryTime() {

        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap().get(EXPIRY_TIME))) {
            return Long.parseLong(getAuthenticatorConfig().getParameterMap().get(EXPIRY_TIME));
        }
        return DEFAULT_EXPIRY_TIME;
    }

    private User getUser(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        User user = null;
        String tenantDomain = authenticatedUser.getTenantDomain();
        if (tenantDomain != null) {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            try {
                UserRealm userRealm = MagicLinkServiceDataHolder.getInstance().getRealmService()
                        .getTenantUserRealm(tenantId);
                if (userRealm != null) {
                    UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                    List<User> userList = ((AbstractUserStoreManager) userStoreManager).getUserListWithID(
                            USERNAME_CLAIM, authenticatedUser.getUserName(), null);
                    if (CollectionUtils.isEmpty(userList)) {
                        return null;
                    }
                    if (userList.size() > 1) {
                        if (log.isDebugEnabled()) {
                            log.debug("There are more than one user with the provided username claim value: "
                                    + authenticatedUser.getUserName());
                        }
                        return null;
                    }
                    user = userList.get(0);
                } else {
                    log.error("Cannot find the user realm for the given tenant: " + tenantDomain);
                }
            } catch (UserStoreException e) {
                String msg = "getUserListWithID function failed while retrieving the user list.";
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
                throw new AuthenticationFailedException(msg, e);
            }
        }
        return user;
    }
}
