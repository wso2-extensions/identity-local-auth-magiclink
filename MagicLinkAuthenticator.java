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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.magiclink.config.MagicLinkUtils;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authenticator of MagicLink.
 */
public class MagicLinkAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(MagicLinkAuthenticator.class);

    /**
     * @param request  The httpServletRequest.
     * @param response The httpServletResponse.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException In occasions of failing to send the magicToken to the user.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        context.setProperty("authentication", "MagicLink");
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        String username;
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUser = stepConfig.getAuthenticatedUser();
            username = authenticatedUser.getUserName();
            try {
                JWTGenerator jwtGenerator = new JWTGenerator();
                String magicToken = jwtGenerator.generateToken(authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserName(), context.getContextIdentifier(),
                        MagicLinkUtils.getConfiguration(context, "Issuer"),
                        MagicLinkUtils.getConfiguration(context, "Audience"),
                        MagicLinkUtils.getConfiguration(context, "Duration")).serialize();
                context.setProperty("magicLink", magicToken);
                if (StringUtils.isNotEmpty(magicToken)) {
                    this.triggerEvent(username, authenticatedUser.getUserStoreDomain(),
                            authenticatedUser.getTenantDomain(), magicToken);
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Error while initiating request.", e);
            }
            try {
                String url = ServiceURLBuilder.create().addPath(MagicLinkAuthenticatorConstants.
                        MAGICLINK_NOTIFICATION_PAGE).build().getAbsolutePublicURL();
                response.sendRedirect(url);
            } catch (IOException | URLBuilderException e) {
                log.error("Error while redirecting to the notification page.", e);
            }
            break;
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
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (StringUtils.isEmpty(request.getParameter("mL"))) {
            log.isDebugEnabled();
            throw new InvalidCredentialsException("MagicToken cannot be null.");
        } else {
            String userToken = request.getParameter("mL");
            try {
                if (JWTValidator.validate(userToken, context.getTenantDomain())) {
                    String username = JWTValidator.getUsername(userToken);
                    context.setSubject(AuthenticatedUser.
                            createLocalAuthenticatedUserFromSubjectIdentifier(username));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Given MagicToken is not valid");
                    }
                    throw new AuthenticationFailedException("MagicToken is not valid");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("validation failure", e);
            }
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
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

        return StringUtils.isNotEmpty(httpServletRequest.getParameter("mL")) &&
                StringUtils.isEmpty(httpServletRequest.getParameter("mL"))
                || StringUtils.isNotEmpty(httpServletRequest.getParameter("mL"));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return JWTValidator.getSessionDataKey(httpServletRequest.getParameter("mL"));
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
        properties.put("TEMPLATE_TYPE", "magiclink");
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            MagicLinkServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException var12) {
            String errorMsg = "Error occurred while calling triggerNotification. " + var12.getMessage();
            throw new AuthenticationFailedException(errorMsg, var12.getCause());
        }
    }
}

