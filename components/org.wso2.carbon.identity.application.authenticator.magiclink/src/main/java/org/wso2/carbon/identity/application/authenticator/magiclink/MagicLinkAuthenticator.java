/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCache;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheEntry;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheKey;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.application.authenticator.magiclink.util.MagicLinkAuthErrorConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.AUTH_TYPE;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.IDF;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.RESTART_FLOW;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.BLOCKED_USERSTORE_DOMAINS_LIST;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.BLOCKED_USERSTORE_DOMAINS_SEPARATOR;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.DEFAULT_EXPIRY_TIME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.EXPIRY_TIME;

/**
 * Authenticator of MagicLink.
 */
public class MagicLinkAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(MagicLinkAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (isIdentifierFirstRequest(request)) {
            if (context.isLogoutRequest()) {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
            if (getName().equals(context.getProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR))) {
                context.setRetrying(true);
            }
            if (canResolveUserFromIdfAuthenticationResponse(request, context)) {
                setResolvedUserInContext(request, context);
            } else {
                setUnresolvedUserInContext(request, context);
            }
            initiateAuthenticationRequest(request, response, context);
            context.setCurrentAuthenticator(getName());
            context.setRetrying(false);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        return super.process(request, response, context);
    }

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

        if (context.getLastAuthenticatedUser() == null) {
            context.setProperty(MagicLinkAuthenticatorConstants.IS_IDF_INITIATED_FROM_MAGIC_LINK_AUTH, true);
            String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            String queryParams = context.getContextIdIncludedQueryParams();

            try {
                String retryParam = "";
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
                response.sendRedirect(loginPage + ("?" + queryParams)
                        + MagicLinkAuthenticatorConstants.AUTHENTICATORS +
                        MagicLinkAuthenticatorConstants.IDF_HANDLER_NAME + ":" +
                        MagicLinkAuthenticatorConstants.LOCAL + retryParam);
            } catch (IOException e) {
                org.wso2.carbon.identity.application.common.model.User user =
                        org.wso2.carbon.identity.application.common.model.User
                                .getUserFromUserName(request.getParameter(MagicLinkAuthenticatorConstants.USER_NAME));
                throw new AuthenticationFailedException(
                        MagicLinkAuthErrorConstants.ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                        e.getMessage(),
                        user, e);
            }
        } else {
            User user = getUser(context.getLastAuthenticatedUser());
            if (user != null) {
                MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
                String magicToken = TokenGenerator.generateToken(MagicLinkAuthenticatorConstants.TOKEN_LENGTH);
                magicLinkAuthContextData.setMagicToken(magicToken);
                magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis());
                magicLinkAuthContextData.setUser(user);
                magicLinkAuthContextData.setSessionDataKey(context.getContextIdentifier());

                MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(magicToken);
                MagicLinkAuthContextCacheEntry cacheEntry =
                        new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);
                MagicLinkAuthContextCache.getInstance().addToCache(cacheKey, cacheEntry);

                if (StringUtils.isNotEmpty(magicToken)) {
                    String expiryTime =
                            TimeUnit.SECONDS.toMinutes(getExpiryTime()) + " " + TimeUnit.MINUTES.name().toLowerCase();
                    triggerEvent(user.getUsername(), user.getUserStoreDomain(), user.getTenantDomain(), magicToken,
                            context.getServiceProviderName(), expiryTime);
                }
            }
            try {
                String url = ServiceURLBuilder.create()
                        .addPath(MagicLinkAuthenticatorConstants.MAGIC_LINK_NOTIFICATION_PAGE).build()
                        .getAbsolutePublicURL();
                response.sendRedirect(url);
            } catch (IOException e) {
                throw new AuthenticationFailedException(
                        "Error while redirecting to the magic link notification page.", e);
            } catch (URLBuilderException e) {
                throw new AuthenticationFailedException(
                        "Error while building the magic link notification page URL.", e);
            }
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
     * Get the friendly name of the Authenticator.
     */
    @Override
    public String getFriendlyName() {

        return MagicLinkAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        if (isIdentifierFirstRequest(httpServletRequest)) {
            String userName = httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.USER_NAME);
            String restart = httpServletRequest.getParameter(RESTART_FLOW);

            return userName != null || restart != null;
        }
        return StringUtils.isNotEmpty(
                httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String magicToken = request.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN);

        if (StringUtils.isEmpty(magicToken)) {
            return null;
        }

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(magicToken);
        MagicLinkAuthContextCacheEntry cacheEntry = MagicLinkAuthContextCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry != null) {
            return cacheEntry.getMagicLinkAuthContextData().getSessionDataKey();
        }
        return null;
    }

    /**
     * Get the name of the Authenticator.
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
     * @param applicationName The application name.
     * @param expiryTime      The expiry time.
     * @throws AuthenticationFailedException In occasions of failing to send the email to the user.
     */
    protected void triggerEvent(String username, String userStoreDomain, String tenantDomain, String magicToken,
            String applicationName, String expiryTime) throws AuthenticationFailedException {

        String eventName = "TRIGGER_NOTIFICATION";
        HashMap<String, Object> properties = new HashMap<>();
        properties.put("user-name", username);
        properties.put("userstore-domain", userStoreDomain);
        properties.put("tenant-domain", tenantDomain);
        properties.put("magicToken", magicToken);
        properties.put("TEMPLATE_TYPE", "magicLink");
        properties.put("application-name", applicationName);
        properties.put("expiry-time", expiryTime);
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            MagicLinkServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = String.format(
                    "Error occurred while sending the notification for the user: %s in the tenant: %s", username,
                    tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }

    private boolean isMagicTokenValid(MagicLinkAuthContextCacheEntry cacheEntry) {

        if (cacheEntry != null) {
            long currentTimestamp = System.currentTimeMillis();
            long createdTimestamp = cacheEntry.getMagicLinkAuthContextData().getCreatedTimestamp();
            long tokenValidityPeriod = TimeUnit.SECONDS.toMillis(getExpiryTime());
            // Validate whether the token is expired.
            return currentTimestamp - createdTimestamp < tokenValidityPeriod;
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
                    if (userList.isEmpty()) {
                        userList = ((AbstractUserStoreManager) userStoreManager).getUserListWithID(
                                EMAIL_ADDRESS_CLAIM, authenticatedUser.getUserName(), null);
                    }
                    userList = getValidUsers(userList);
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

    /**
     * This method will be deprecated soon.
     *
     * @param userList Users list.
     * @return A valid users list after removing blocked users.
     */
    private List<User> getValidUsers(List<User> userList) {

        List<String> blockedUserStoreDomainsList = getBlockedUserStoreDomainsList();
        if (CollectionUtils.isEmpty(blockedUserStoreDomainsList)) {
            return userList;
        }
        List<User> validUserList = new ArrayList<>();
        for (User user : userList) {
            if (!blockedUserStoreDomainsList.contains(user.getUserStoreDomain())) {
                validUserList.add(user);
            }
        }
        return validUserList;
    }

    private List<String> getBlockedUserStoreDomainsList() {

        List<String> blockedUserStoreDomainsList = new ArrayList<>();
        if (StringUtils.isNotBlank(getAuthenticatorConfig().getParameterMap().get(BLOCKED_USERSTORE_DOMAINS_LIST))) {
            CollectionUtils.addAll(blockedUserStoreDomainsList,
                    StringUtils.split(getAuthenticatorConfig().getParameterMap().get(BLOCKED_USERSTORE_DOMAINS_LIST),
                            BLOCKED_USERSTORE_DOMAINS_SEPARATOR));
        }
        return blockedUserStoreDomainsList;
    }

    private String getIdentifierFromRequest(HttpServletRequest request) {

        return request.getParameter(MagicLinkAuthenticatorConstants.USER_NAME);
    }

    private boolean canResolveUserFromIdfAuthenticationResponse(HttpServletRequest request,
                                                                AuthenticationContext context)
            throws AuthenticationFailedException {

        String identifierFromRequest = getIdentifierFromRequest(request);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new InvalidCredentialsException(MagicLinkAuthErrorConstants.ErrorMessages.EMPTY_USERNAME.getCode(),
                    MagicLinkAuthErrorConstants.ErrorMessages.EMPTY_USERNAME.getMessage());
        }
        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (MapUtils.isNotEmpty(runtimeParams)) {
            String skipPreProcessUsername = runtimeParams
                    .get(MagicLinkAuthenticatorConstants.SKIP_IDENTIFIER_PRE_PROCESS);
            return !Boolean.parseBoolean(skipPreProcessUsername);
        }
        return true;
    }

    /**
     * This method is used to resolve the user from authentication response from identifier handler.
     *
     * @param request  The httpServletRequest.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private void setResolvedUserInContext(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = getIdentifierFromRequest(request);

        Optional<String> validatedEmailUsername = validateEmailUsername(username, context);
        if (validatedEmailUsername.isPresent()) {
            username = validatedEmailUsername.get();
        }

        String userId = null;
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        Map<String, Object> authProperties = context.getProperties();
        if (MapUtils.isEmpty(authProperties)) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        // Resolve user from multi attribute login.
        Optional<User> multiAttributeLoginUser = UserResolver.resolveUserFromMultiAttributeLogin(
                context, username);
        if (multiAttributeLoginUser.isPresent()) {
            User user = multiAttributeLoginUser.get();
            tenantAwareUsername = user.getUsername();
            username = UserCoreUtil.addTenantDomainToEntry(user.getUsername(),
                    context.getTenantDomain());
            userId = user.getUserID();
        }

        // Resolve user during B2B flow.
        Optional<User> orgUser = UserResolver.resolveUserFromOrganizationHierarchy(context, tenantAwareUsername,
                username);
        if (orgUser.isPresent()) {
            User user = orgUser.get();
            tenantAwareUsername = user.getUsername();
            username = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, user.getTenantDomain());
            userId = user.getUserID();
        }

        if (StringUtils.isBlank(userId)) {
            // Resolve user from user store
            Optional<User> userStoreUser = UserResolver.resolveUserFromUserStore(tenantDomain,
                    tenantAwareUsername, username);
            if (userStoreUser.isPresent()) {
                User user = userStoreUser.get();
                userId = user.getUserID();
            }
        }

        validateUsername(userId, username);

        username = FrameworkUtils.prependUserStoreDomainToName(username);
        authProperties.put(MagicLinkAuthenticatorConstants.USER_NAME, username);
        persistUsername(context, username);
        setSubjectInContextWithUserId(context, userId, tenantAwareUsername, username, tenantDomain);
    }

    private Optional<String> validateEmailUsername(String identifierFromRequest, AuthenticationContext context)
    throws InvalidCredentialsException {

        if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
            FrameworkUtils.validateUsername(identifierFromRequest, context);
            return Optional.ofNullable(FrameworkUtils.preprocessUsername(identifierFromRequest, context));
        }
        return Optional.empty();
    }

    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        //Identifier first is the first authenticator.
        context.getPreviousAuthenticatedIdPs().clear();
        context.addAuthenticatorParams(contextParams);
    }

    private void setSubjectInContextWithUserId(AuthenticationContext context, String userId, String tenantAwareUsername,
                                     String username, String tenantDomain) {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(userId);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
        user.setTenantDomain(tenantDomain);
        context.setSubject(user);
    }

    private void validateUsername(String userId, String username)
            throws AuthenticationFailedException {

        if (getAuthenticatorConfig().getParameterMap() == null) {
            return;
        }
        String validateUsername = getAuthenticatorConfig().getParameterMap()
                .get(MagicLinkAuthenticatorConstants.VALIDATE_USERNAME);
        if (!Boolean.parseBoolean(validateUsername)) {
            return;
        }
        if (StringUtils.isBlank(userId)) {
            if (log.isDebugEnabled()) {
                log.debug("User does not exists");
            }
            if (IdentityUtil.threadLocalProperties.get()
                    .get(MagicLinkAuthenticatorConstants.RE_CAPTCHA_USER_DOMAIN) != null) {
                username = IdentityUtil.addDomainToName(
                        username, IdentityUtil.threadLocalProperties.get()
                                .get(MagicLinkAuthenticatorConstants.RE_CAPTCHA_USER_DOMAIN).toString());
            }
            IdentityUtil.threadLocalProperties.get()
                    .remove(MagicLinkAuthenticatorConstants.RE_CAPTCHA_USER_DOMAIN);
            throw new InvalidCredentialsException(
                    MagicLinkAuthErrorConstants.ErrorMessages.USER_DOES_NOT_EXISTS.getCode(),
                    MagicLinkAuthErrorConstants.ErrorMessages.USER_DOES_NOT_EXISTS.getMessage(),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username));
        }
    }

    private void setSubjectInContextWithoutUserId(AuthenticationContext context, String identifierFromRequest) {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(identifierFromRequest);
        context.setSubject(user);
    }

    private void setUnresolvedUserInContext(HttpServletRequest request, AuthenticationContext context) {

        String identifierFromRequest = getIdentifierFromRequest(request);
        persistUsername(context, identifierFromRequest);
        setSubjectInContextWithoutUserId(context, identifierFromRequest);
    }

    /**
     * Check if request type is identifier first.
     *
     * @param request HttpServletRequest.
     * @return boolean.
     */
    private boolean isIdentifierFirstRequest(HttpServletRequest request) {

        String authType = request.getParameter(AUTH_TYPE);
        return IDF.equals(authType);
    }
}
