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

import org.mockito.ArgumentCaptor;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.magiclink.TokenGenerator;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkExecutorContextData;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.user.core.common.User;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.magiclink.executor.MagicLinkExecutor.MAGIC_LINK_PASSWORD_RECOVERY_TEMPLATE;
import static org.wso2.carbon.identity.application.authenticator.magiclink.executor.MagicLinkExecutor.MAGIC_LINK_SIGN_UP_TEMPLATE;
import static org.wso2.carbon.identity.application.authenticator.magiclink.executor.MagicLinkExecutorConstants.MAGIC_LINK_EXECUTOR_CONTEXT;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.PASSWORD_RECOVERY;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.REGISTRATION;

/**
 * Unit tests for the MagicLinkExecutor class.
 */
@PrepareForTest({
        FileBasedConfigurationBuilder.class,
        MagicLinkServiceDataHolder.class,
        LoggerUtils.class,
        TokenGenerator.class
})
@PowerMockIgnore({"jdk.internal.reflect.*", "javax.management.*", "javax.xml.*", "javax.crypto.*", "javax.activation.*",
        "org.xml.*", "org.w3c.*"})
public class MagicLinkExecutorTest extends PowerMockTestCase {

    private static final String TEST_USERNAME = "user";
    private static final String TEST_EMAIL = "user@test.com";
    private static final String TEST_TOKEN = "sample-token";
    private static final String TEST_CONTEXT_ID = "ctx-123";
    private static final String TEST_TENANT = "carbon.super";

    private MagicLinkExecutor executor;
    private FlowExecutionContext context;
    private FlowUser flowUser;
    private IdentityEventService eventService;

    @BeforeMethod
    public void setup() {

        context = mock(FlowExecutionContext.class);
        flowUser = mock(FlowUser.class);
        eventService = mock(IdentityEventService.class);

        PowerMockito.mockStatic(LoggerUtils.class);
        PowerMockito.mockStatic(FileBasedConfigurationBuilder.class);
        PowerMockito.mockStatic(MagicLinkServiceDataHolder.class);
        PowerMockito.mockStatic(TokenGenerator.class);

        FileBasedConfigurationBuilder builder = mock(FileBasedConfigurationBuilder.class);
        MagicLinkServiceDataHolder holder = mock(MagicLinkServiceDataHolder.class);

        AuthenticatorConfig config = mock(AuthenticatorConfig.class);
        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(MagicLinkAuthenticatorConstants.EXPIRY_TIME, "300");
        when(config.getParameterMap()).thenReturn(paramMap);

        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(builder);
        when(builder.getAuthenticatorBean(MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME)).thenReturn(config);

        when(holder.getIdentityEventService()).thenReturn(eventService);
        when(MagicLinkServiceDataHolder.getInstance()).thenReturn(holder);

        PowerMockito.when(TokenGenerator.generateToken(anyInt())).thenReturn(TEST_TOKEN);

        executor = new MagicLinkExecutor();
        when(context.getFlowUser()).thenReturn(flowUser);
    }

    @Test
    public void testGetName() {

        assertEquals(executor.getName(), "MagicLinkExecutor");
    }

    @Test
    public void testGetInitiationData() {

        List<String> data = executor.getInitiationData();
        assertEquals(data.size(), 1);
        assertTrue(data.contains(EMAIL_ADDRESS_CLAIM));
    }

    @Test
    public void testExecuteWithNonLocallyManagedCredentials() throws Exception {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_EMAIL);
        when(flowUser.isCredentialsManagedLocally()).thenReturn(false);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT);
        when(context.getContextIdentifier()).thenReturn(TEST_CONTEXT_ID);
        when(context.getPortalUrl()).thenReturn("https://portal");
        when(context.getFlowType()).thenReturn("signup");
        when(context.getUserInputData()).thenReturn(new HashMap<>());
        when(context.getProperties()).thenReturn(new HashMap<>());

        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        assertTrue(response.getRequiredData().contains(MagicLinkExecutor.MLT));
        verify(eventService, never()).handleEvent(any(Event.class));
    }

    @Test
    public void testExecuteWithLockedAccount() throws Exception {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_EMAIL);
        when(flowUser.isCredentialsManagedLocally()).thenReturn(true);
        when(flowUser.isAccountLocked()).thenReturn(true);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT);
        when(context.getContextIdentifier()).thenReturn(TEST_CONTEXT_ID);
        when(context.getPortalUrl()).thenReturn("https://portal");
        when(context.getFlowType()).thenReturn("signup");
        when(context.getUserInputData()).thenReturn(new HashMap<>());
        when(context.getProperties()).thenReturn(new HashMap<>());

        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        assertTrue(response.getRequiredData().contains(MagicLinkExecutor.MLT));
        verify(eventService, never()).handleEvent(any(Event.class));
    }

    @Test
    public void testExecuteWithDisabledAccount() throws Exception {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_EMAIL);
        when(flowUser.isCredentialsManagedLocally()).thenReturn(true);
        when(flowUser.isAccountLocked()).thenReturn(false);
        when(flowUser.isAccountDisabled()).thenReturn(true);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT);
        when(context.getContextIdentifier()).thenReturn(TEST_CONTEXT_ID);
        when(context.getPortalUrl()).thenReturn("https://portal");
        when(context.getFlowType()).thenReturn("signup");
        when(context.getUserInputData()).thenReturn(new HashMap<>());
        when(context.getProperties()).thenReturn(new HashMap<>());

        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        assertTrue(response.getRequiredData().contains(MagicLinkExecutor.MLT));
        verify(eventService, never()).handleEvent(any(Event.class));
    }

    @Test
    public void testExecuteInitiatesMagicLink() throws Exception {

        prepareInitiationContext();
        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        assertTrue(response.getRequiredData().contains(MagicLinkExecutor.MLT));
    }

    @Test
    public void testExecuteHandlesNotificationFailure() throws Exception {

        prepareInitiationContext();
        doThrow(new IdentityEventException("error")).when(eventService).handleEvent(any(Event.class));
        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
    }

    @Test
    public void testExecuteProcessesMagicLinkSuccess() throws Exception {

        prepareVerificationContext(true);
        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_COMPLETE);
    }

    @Test
    public void testExecuteFailsWithMissingToken() throws Exception {

        prepareVerificationContext(false);
        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertNotNull(response.getErrorMessage());
    }

    @Test
    public void testExecuteFailsWithExpiredToken() throws Exception {

        prepareVerificationContext(true, -999999L);
        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertTrue(response.getErrorMessage().contains("magic.link.error.message"));
    }

    @Test
    public void testRollbackReturnsNull() throws Exception {

        assertNull(executor.rollback(context));
    }

    @Test
    public void testSetMagicLinkTemplateTypeForRegistrationFlow() throws Exception {

        prepareInitiationContext();
        when(context.getFlowType()).thenReturn(REGISTRATION.name());
        ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
        executor.execute(context);
        verify(eventService).handleEvent(eventCaptor.capture());
        Event capturedEvent = eventCaptor.getValue();
        assertEquals(capturedEvent.getEventProperties().get(MagicLinkAuthenticatorConstants.TEMPLATE_TYPE),
                MAGIC_LINK_SIGN_UP_TEMPLATE);
    }

    @Test
    public void testSetMagicLinkTemplateTypeForPasswordRecoveryFlow() throws Exception {

        prepareInitiationContext();
        when(context.getFlowType()).thenReturn(PASSWORD_RECOVERY.name());
        ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
        executor.execute(context);
        verify(eventService).handleEvent(eventCaptor.capture());
        Event capturedEvent = eventCaptor.getValue();
        assertEquals(capturedEvent.getEventProperties().get(MagicLinkAuthenticatorConstants.TEMPLATE_TYPE),
                MAGIC_LINK_PASSWORD_RECOVERY_TEMPLATE);
    }

    @Test
    public void testSetMagicLinkTemplateTypeForUnknownFlow() throws Exception {

        prepareInitiationContext();
        when(context.getFlowType()).thenReturn("UNKNOWN_FLOW");
        ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
        executor.execute(context);
        verify(eventService).handleEvent(eventCaptor.capture());
        Event capturedEvent = eventCaptor.getValue();
        assertNull(capturedEvent.getEventProperties().get(MagicLinkAuthenticatorConstants.TEMPLATE_TYPE));
    }

    @Test
    public void testPasswordRecoveryFlowWithMissingEmail() throws Exception {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(null);
        when(flowUser.isCredentialsManagedLocally()).thenReturn(true);
        when(flowUser.isAccountLocked()).thenReturn(false);
        when(flowUser.isAccountDisabled()).thenReturn(false);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT);
        when(context.getContextIdentifier()).thenReturn(TEST_CONTEXT_ID);
        when(context.getPortalUrl()).thenReturn("https://portal");
        when(context.getFlowType()).thenReturn(PASSWORD_RECOVERY.name());
        when(context.getUserInputData()).thenReturn(new HashMap<>());
        when(context.getProperties()).thenReturn(new HashMap<>());

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);

        verify(eventService, never()).handleEvent(any(Event.class));
        assertNull(response.getContextProperties().get(MAGIC_LINK_EXECUTOR_CONTEXT));
    }

    @Test
    public void testPasswordRecoveryFlowWithValidEmail() throws Exception {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_EMAIL);
        when(flowUser.isCredentialsManagedLocally()).thenReturn(true);
        when(flowUser.isAccountLocked()).thenReturn(false);
        when(flowUser.isAccountDisabled()).thenReturn(false);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT);
        when(context.getContextIdentifier()).thenReturn(TEST_CONTEXT_ID);
        when(context.getPortalUrl()).thenReturn("https://portal");
        when(context.getFlowType()).thenReturn(PASSWORD_RECOVERY.name());
        when(context.getUserInputData()).thenReturn(new HashMap<>());
        when(context.getProperties()).thenReturn(new HashMap<>());

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);

        verify(eventService).handleEvent(any(Event.class));
        assertNotNull(response.getContextProperties().get(MAGIC_LINK_EXECUTOR_CONTEXT));
    }

    private void prepareInitiationContext() {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_EMAIL);
        when(flowUser.isCredentialsManagedLocally()).thenReturn(true);
        when(flowUser.isAccountLocked()).thenReturn(false);
        when(flowUser.isAccountDisabled()).thenReturn(false);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT);
        when(context.getContextIdentifier()).thenReturn(TEST_CONTEXT_ID);
        when(context.getPortalUrl()).thenReturn("https://portal");
        when(context.getFlowType()).thenReturn("signup");
        when(context.getUserInputData()).thenReturn(new HashMap<>());
        when(context.getProperties()).thenReturn(new HashMap<>());
    }

    private void prepareVerificationContext(boolean includeToken) {

        prepareVerificationContext(includeToken, System.currentTimeMillis());
    }

    private void prepareVerificationContext(boolean includeToken, long timestamp) {

        when(flowUser.getUsername()).thenReturn(TEST_USERNAME);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_EMAIL);

        Map<String, String> input = new HashMap<>();
        if (includeToken) {
            input.put(MagicLinkExecutor.MLT, TEST_TOKEN);
        }
        when(context.getUserInputData()).thenReturn(input);

        MagicLinkExecutorContextData data = new MagicLinkExecutorContextData();
        data.setMagicToken(TEST_TOKEN);
        data.setCreatedTimestamp(System.currentTimeMillis() + timestamp);
        data.setFlowID(TEST_CONTEXT_ID);

        Map<String, Object> props = new HashMap<>();
        props.put(MAGIC_LINK_EXECUTOR_CONTEXT, data);

        when(context.getProperty(MAGIC_LINK_EXECUTOR_CONTEXT)).thenReturn(data);
        when(context.getProperties()).thenReturn(props);
    }
}
