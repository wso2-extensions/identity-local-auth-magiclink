/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.magiclink.executor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.magiclink.TokenGenerator;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.DEFAULT_EXPIRY_TIME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.EXPIRY_TIME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.LogConstants.ActionIDs.SEND_MAGIC_LINK;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.LogConstants.MAGIC_LINK_AUTH_SERVICE;

/**
 * MagicLinkExecutor is responsible for handling the magic link flow.
 */
public class MagicLinkExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(MagicLinkExecutor.class);
    public static final String MLT = "mlt";
    public static final String PORTAL_URL = "portalUrl";

    @Override
    public String getName() {

        return "MagicLinkExecutor";
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) throws FlowEngineException {

        ExecutorResponse response = new ExecutorResponse();
        Map<String, Object> contextProperties = new HashMap<>();
        response.setContextProperty(contextProperties);

        validateRequiredData(context);

        if (isInitiation(context)) {
            return initiateMagicLink(context, response);
        } else {
            return processMagicLink(context, response);
        }
    }

    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        initiationData.add(USERNAME_CLAIM);
        initiationData.add(EMAIL_ADDRESS_CLAIM);
        return initiationData;
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        return null;
    }

    private ExecutorResponse initiateMagicLink(FlowExecutionContext context, ExecutorResponse response) {

        String username = context.getFlowUser().getUsername();
        String emailAddress = (String) context.getFlowUser().getClaim(EMAIL_ADDRESS_CLAIM);

        User user = new User();
        user.setUsername(username);
        user.setTenantDomain(context.getTenantDomain());
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put(USERNAME_CLAIM, username);
        attributes.put(EMAIL_ADDRESS_CLAIM, emailAddress);
        user.setAttributes(attributes);

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        String magicToken = TokenGenerator.generateToken(MagicLinkAuthenticatorConstants.TOKEN_LENGTH);
        magicLinkAuthContextData.setMagicToken(magicToken);
        magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis());
        magicLinkAuthContextData.setUser(user);
        magicLinkAuthContextData.setSessionDataKey(context.getContextIdentifier());

        response.getContextProperties().put(MagicLinkAuthenticatorConstants.MAGIC_LINK_AUTH_CONTEXT_DATA,
                magicLinkAuthContextData);

        String expiryTime =
                TimeUnit.SECONDS.toMinutes(getExpiryTime()) + " " + TimeUnit.MINUTES.name().toLowerCase();
        magicToken = magicToken + "&" + "flowId=" + context.getContextIdentifier();
        context.getUserInputData().put(MLT, magicToken);
        triggerEvent(context, user, magicToken, expiryTime, context.getPortalUrl());
        return clientInputRequiredResponse(response, MLT);
    }

    private ExecutorResponse processMagicLink(FlowExecutionContext context, ExecutorResponse response) {

        String magicToken = context.getUserInputData().get(MLT);
        if (magicToken == null || magicToken.isEmpty()) {
            return userErrorResponse(response, "Magic Link token is required for verification.");
        }

        MagicLinkAuthContextData magicLinkAuthContextData = (MagicLinkAuthContextData)
                context.getProperty(MagicLinkAuthenticatorConstants.MAGIC_LINK_AUTH_CONTEXT_DATA);
        if (magicLinkAuthContextData == null) {
            return userErrorResponse(response, "Invalid or expired magic link token.");
        }

        if (!isMagicTokenValid(magicLinkAuthContextData)) {
            return userErrorResponse(response, "Magic link token has expired.");
        }

        User user = magicLinkAuthContextData.getUser();
        if (user == null || user.getUsername() == null) {
            return userErrorResponse(response, "User information is missing in the magic link token.");
        }

        if (!user.getUsername().equals(context.getFlowUser().getUsername())) {
            return userErrorResponse(response, "Username mismatch in the magic link token.");
        }

        context.getProperties().remove(MagicLinkAuthenticatorConstants.MAGIC_LINK_AUTH_CONTEXT_DATA);
        response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
        return response;
    }

    /**
     * Method to Trigger the Magic Link event.
     *
     * @param user       The user.
     * @param magicToken The magicToken sent to email.
     * @param expiryTime The expiry time.
     * @param portalURL  The callback URL to redirect after clicking the magic link.
     */
    private void triggerEvent(FlowExecutionContext context, User user, String magicToken, String expiryTime,
                              String portalURL) {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(MagicLinkAuthenticatorConstants.TEMPLATE_TYPE, "magicLinkSignUp");
        properties.put(MagicLinkAuthenticatorConstants.EXPIRYTIME, expiryTime);
        properties.put(MagicLinkAuthenticatorConstants.MAGIC_TOKEN, magicToken);
        properties.put(PORTAL_URL, portalURL);
        properties.put(NotificationConstants.ARBITRARY_SEND_TO, user.getAttributes().get(EMAIL_ADDRESS_CLAIM));
        properties.put(NotificationConstants.FLOW_TYPE, context.getFlowType());
        Event identityMgtEvent = new Event(eventName, properties);
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(MAGIC_LINK_AUTH_SERVICE, SEND_MAGIC_LINK);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .inputParam("user store domain", user.getUserStoreDomain())
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(user.getUsername()) : user.getUsername())
                    .inputParam(LogConstants.InputKeys.USER_ID, user.getUserID());
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
            LOG.error(errorMsg);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Failed to send magic link notification.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        }
    }

    private boolean isInitiation(FlowExecutionContext context) {

        return context.getUserInputData().get(MLT) == null &&
                context.getProperty(MagicLinkAuthenticatorConstants.MAGIC_LINK_AUTH_CONTEXT_DATA) == null;
    }

    private void validateRequiredData(FlowExecutionContext context) throws FlowEngineException {

        if (context.getFlowUser().getUsername() == null) {
            throw new FlowEngineClientException("Username is required for Magic Link registration.");
        }
        if (context.getFlowUser().getClaim(EMAIL_ADDRESS_CLAIM) == null) {
            throw new FlowEngineClientException("Email address is required for Magic Link registration.");
        }
    }

    private ExecutorResponse clientInputRequiredResponse(ExecutorResponse response, String... fields) {

        response.setResult(Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED);
        response.setRequiredData(Arrays.asList(fields));
        return response;
    }

    private ExecutorResponse userErrorResponse(ExecutorResponse response, String errorMessage) {

        response.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
        response.setErrorMessage(errorMessage);
        return response;
    }

    /**
     * Validate the magic token.
     *
     * @param magicLinkAuthContextData The magic link authentication context data.
     * @return true if the token is valid, false otherwise.
     */
    private boolean isMagicTokenValid(MagicLinkAuthContextData magicLinkAuthContextData) {

        if (magicLinkAuthContextData != null) {
            long currentTimestamp = System.currentTimeMillis();
            long createdTimestamp = magicLinkAuthContextData.getCreatedTimestamp();
            long tokenValidityPeriod = TimeUnit.SECONDS.toMillis(getExpiryTime());
            return currentTimestamp - createdTimestamp < tokenValidityPeriod;
        }
        return false;
    }

    /**
     * Get the expiry time for the magic link token.
     *
     * @return Expiry time in seconds.
     */
    private long getExpiryTime() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap<>());
        }
        if (StringUtils.isNotBlank(authConfig.getParameterMap().get(EXPIRY_TIME))) {
            return Long.parseLong(authConfig.getParameterMap().get(EXPIRY_TIME));
        }
        return DEFAULT_EXPIRY_TIME;
    }
}
