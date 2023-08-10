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
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCache;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheEntry;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheKey;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.application.authenticator.magiclink.util.MagicLinkAuthErrorConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.RESTART_FLOW;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.BLOCKED_USERSTORE_DOMAINS_LIST;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.BLOCKED_USERSTORE_DOMAINS_SEPARATOR;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.DEFAULT_EXPIRY_TIME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.EXPIRY_TIME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.LogConstants.ActionIDs.SEND_MAGIC_LINK;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.LogConstants.ActionIDs.VALIDATE_MAGIC_LINK_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.LogConstants.MAGIC_LINK_AUTH_SERVICE;

/**
 * Authenticator of MagicLink.
 */
public class MagicLinkAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(MagicLinkAuthenticator.class);
    private AuthenticationContext authenticationContext;

    /**
     * Processes the authentication or logout flow for the Authenticator.
     *
     * @param request  The httpServletRequest.
     * @param response The httpServletResponse.
     * @param context  The authentication context.
     * @return The AuthenticatorFlowStatus indicating the status of the flow.
     * @throws AuthenticationFailedException If the authentication process fails.
     * @throws LogoutFailedException         If the logout process fails.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {

        this.authenticationContext = context;
        if (!isIdfInitiatedFromMagicLink()) {
            return super.process(request, response, authenticationContext);
        }
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        if (StringUtils.equals(getName(), (String) context.getProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR))) {
            context.setRetrying(true);
        }
        User user = resolveUser(request, authenticationContext);
        setResolvedUserInContext(authenticationContext, user);
        authenticationContext.setProperty(MagicLinkAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, false);
        initiateAuthenticationRequest(request, response, authenticationContext);
        context.setCurrentAuthenticator(getName());
        context.setRetrying(false);
        return AuthenticatorFlowStatus.INCOMPLETE;
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

        // This diagnostic log will be used to log the details of the authentication redirection at the end of
        // the flow.
        DiagnosticLog.DiagnosticLogBuilder finalDiagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    MAGIC_LINK_AUTH_SERVICE, VALIDATE_MAGIC_LINK_REQUEST);
            diagnosticLogBuilder.resultMessage("Validating magic link authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            finalDiagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    MAGIC_LINK_AUTH_SERVICE, VALIDATE_MAGIC_LINK_REQUEST);
            finalDiagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
        }
        if (context.getLastAuthenticatedUser() == null) {
            context.setProperty(MagicLinkAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
            String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            String queryParams = context.getContextIdIncludedQueryParams();
            try {
                if (log.isDebugEnabled()) {
                    String logMsg = String.format("Redirecting to identifier first flow since " +
                                    "last authenticated user is null in SP: %s",
                            context.getServiceProviderName());
                    log.debug(logMsg);
                }
                String redirectUri = loginPage + ("?" + queryParams) + MagicLinkAuthenticatorConstants.AUTHENTICATORS +
                        MagicLinkAuthenticatorConstants.IDF_HANDLER_NAME + ":" + MagicLinkAuthenticatorConstants.LOCAL;
                response.sendRedirect(redirectUri);
                if (LoggerUtils.isDiagnosticLogsEnabled() && finalDiagnosticLogBuilder != null) {
                    finalDiagnosticLogBuilder.resultMessage("Redirecting to identifier first flow since the last " +
                                    "authenticated user is null.")
                            .inputParam(LogConstants.InputKeys.REDIREDCT_URI, redirectUri);
                    LoggerUtils.triggerDiagnosticLogEvent(finalDiagnosticLogBuilder);
                }
            } catch (IOException e) {
                org.wso2.carbon.identity.application.common.model.User user =
                        org.wso2.carbon.identity.application.common.model.User
                                .getUserFromUserName(request.getParameter(MagicLinkAuthenticatorConstants.USER_NAME));
                throw new AuthenticationFailedException(
                        MagicLinkAuthErrorConstants.ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                        e.getMessage(), user, e);
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
                    triggerEvent(user, context, magicToken, expiryTime);
                }
            }
            try {
                String url = ServiceURLBuilder.create()
                        .addPath(MagicLinkAuthenticatorConstants.MAGIC_LINK_NOTIFICATION_PAGE).build()
                        .getAbsolutePublicURL();
                response.sendRedirect(url);
                if (LoggerUtils.isDiagnosticLogsEnabled() && finalDiagnosticLogBuilder != null) {
                    finalDiagnosticLogBuilder.resultMessage("Redirecting to magic link notification page.")
                            .inputParam(LogConstants.InputKeys.REDIREDCT_URI, url);
                    LoggerUtils.triggerDiagnosticLogEvent(finalDiagnosticLogBuilder);
                }
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

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    MAGIC_LINK_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing magic link authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
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
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    MAGIC_LINK_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Successfully processed magic link authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            Optional<String> optionalUserId = getUserId(context);
            optionalUserId.ifPresent(userId -> diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, userId));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(MAGIC_LINK_AUTH_SERVICE,
                    FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
        }
        if (isIdfInitiatedFromMagicLink()) {
            if (log.isDebugEnabled()) {
                log.debug("Magic link authenticator is handling identifier first flow ");
            }
            String userName = httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.USER_NAME);
            String restart = httpServletRequest.getParameter(RESTART_FLOW);
            boolean canHandle = StringUtils.isNotEmpty(userName) || StringUtils.isNotEmpty(restart);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null && canHandle) {
                diagnosticLogBuilder.resultMessage("Magic link authenticator is handling identifier first flow.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return canHandle;
        }
        boolean canHandle = StringUtils.isNotEmpty(httpServletRequest.getParameter(
                MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN));
        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null && canHandle) {
            diagnosticLogBuilder.resultMessage("Magic link authenticator is handling the authentication.");
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
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
     * @param user            The user.
     * @param context         The authentication context.
     * @param magicToken      The magicToken sent to email.
     * @param expiryTime      The expiry time.
     */
    protected void triggerEvent(User user, AuthenticationContext context, String magicToken, String expiryTime) {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(MagicLinkAuthenticatorConstants.MAGIC_TOKEN, magicToken);
        properties.put(MagicLinkAuthenticatorConstants.TEMPLATE_TYPE, MagicLinkAuthenticatorConstants.EVENT_NAME);
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        properties.put(MagicLinkAuthenticatorConstants.EXPIRYTIME, expiryTime);
        Event identityMgtEvent = new Event(eventName, properties);
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(MAGIC_LINK_AUTH_SERVICE, SEND_MAGIC_LINK);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .inputParam("user store domain", user.getUserStoreDomain())
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(user.getUsername()) : user.getUsername())
                    .inputParam(LogConstants.InputKeys.USER_ID, user.getUserID())
                    .inputParams(getApplicationDetails(context));
        }
        try {
            MagicLinkServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Successfully sent the magic link notification.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IdentityEventException e) {
            String errorMsg = String.format(
                    "Email notification sending failed for the user: %s in the tenant: %s", user.getUsername(),
                    user.getTenantDomain());
            log.error(errorMsg);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Failed to send magic link notification.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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

    private String validateIdentifierFromRequest(HttpServletRequest request)
            throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(MagicLinkAuthenticatorConstants.USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new InvalidCredentialsException(MagicLinkAuthErrorConstants.ErrorMessages.EMPTY_USERNAME.getCode(),
                    MagicLinkAuthErrorConstants.ErrorMessages.EMPTY_USERNAME.getMessage());
        }
        return identifierFromRequest;
    }

    /**
     * This method is used to resolve the user from authentication response from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @return The resolved User object.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private User resolveUser(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = validateIdentifierFromRequest(request);
        validateEmailUsername(username, context);
        username = FrameworkUtils.preprocessUsername(username, context);
        User user = new User();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setUsername(tenantAwareUsername);
        user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
        user.setTenantDomain(tenantDomain);
        return user;
    }

    private void setResolvedUserInContext(AuthenticationContext context, User user) {

        Map<String, Object> authProperties = context.getProperties();
        if (MapUtils.isEmpty(authProperties)) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        String username = UserCoreUtil.addTenantDomainToEntry(user.getUsername(), user.getTenantDomain());
        username = FrameworkUtils.prependUserStoreDomainToName(username);
        authProperties.put(MagicLinkAuthenticatorConstants.USER_NAME, username);
        addUsernameToContext(context, username);
        setSubjectInContext(context, user);
    }

    private void validateEmailUsername(String identifierFromRequest, AuthenticationContext context)
            throws InvalidCredentialsException {

        if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
            FrameworkUtils.validateUsername(identifierFromRequest, context);
        }
    }

    private void addUsernameToContext(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        //Identifier first is the first authenticator.
        context.getPreviousAuthenticatedIdPs().clear();
        context.addAuthenticatorParams(contextParams);
    }

    private void setSubjectInContext(AuthenticationContext context, User user) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserId(user.getUserID());
        authenticatedUser.setUserName(user.getUsername());
        authenticatedUser.setUserStoreDomain(user.getUserStoreDomain());
        authenticatedUser.setTenantDomain(user.getTenantDomain());
        context.setSubject(authenticatedUser);
    }

    private boolean isIdfInitiatedFromMagicLink() {

        return Boolean.TRUE.equals(
                authenticationContext.getProperty(MagicLinkAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR));
    }

    /** Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map of application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    private Optional<String> getUserId(AuthenticationContext context) {

        return Optional.ofNullable(context.getSubject()).map(authenticatedUser -> {
            try {
                return authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting the user id from the subject.", e);
                }
                return null;
            }
        });
    }
}
