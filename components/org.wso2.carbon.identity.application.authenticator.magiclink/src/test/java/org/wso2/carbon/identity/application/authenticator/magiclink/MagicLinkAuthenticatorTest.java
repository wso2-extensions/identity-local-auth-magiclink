/**
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.com)\.
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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCache;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheEntry;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheKey;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.ACCOUNT_LOCKED;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.DISPLAY_USER_NAME;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.ERROR_PAGE;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.USERNAME_PARAM;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.USER_NAME;

public class MagicLinkAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private static final String USERNAME = "admin";
    private static final String INVALID_USERNAME = "paul";
    private static final String USERNAME_WITH_TENANT_DOMAIN = "admin@carbon.super";
    private static final String DUMMY_MAGIC_TOKEN = "Adafeaf23412vdasdfG6fshs";
    private static final String DEFAULT_SERVER_URL = "http://localhost:9443";
    private static final String DUMMY_LOGIN_PAGEURL = "dummyLoginPageurl";
    private static final String DUMMY_QUERY_PARAMS = "dummyQueryParams";
    private static final String DUMMY_APP_NAME = "dummyAppName";
    private static final String DUMMY_APP_RESOURCE_ID = "dummyAppResourceId";
    private static final int SUPER_TENANT_ID = -1234;
    private MagicLinkAuthenticator magicLinkAuthenticator;
    private String redirect;
    private AutoCloseable closeable;

    // Static mocks.
    private MockedStatic<TokenGenerator> mockedTokenGenerator;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<FrameworkUtils> mockedFrameworkUtils;
    private MockedStatic<MultitenantUtils> mockedMultitenantUtils;
    private MockedStatic<MagicLinkAuthContextCache> mockedMagicLinkAuthContextCache;
    private MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder;
    private MockedStatic<ConfigurationFacade> mockedConfigurationFacade;
    private MockedStatic<UserCoreUtil> mockedUserCoreUtil;
    private MockedStatic<FrameworkServiceDataHolder> mockedFrameworkServiceDataHolder;
    private MockedStatic<LoggerUtils> mockedLoggerUtils;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private IdentityEventService mockIdentityEventService;

    @Mock
    private AccountLockService mockAccountLockService;

    @Mock
    private UserRealm mockUserRealm;

    @Mock
    private AbstractUserStoreManager mockUserStoreManager;

    @Mock
    private MagicLinkAuthContextCache mockMagicLinkAuthContextCache;

    @Mock
    private ConfigurationFacade mockConfigurationFacade;

    @Mock
    ExternalIdPConfig externalIdPConfig;

    private FrameworkServiceDataHolder frameworkServiceDataHolder;

    @BeforeMethod
    public void setUp() {

        closeable = openMocks(this);
        magicLinkAuthenticator = new MagicLinkAuthenticator();
        
        // Initialize static mocks.
        mockedTokenGenerator = Mockito.mockStatic(TokenGenerator.class);
        mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
        mockedIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        mockedFrameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
        mockedMultitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
        mockedMagicLinkAuthContextCache = Mockito.mockStatic(MagicLinkAuthContextCache.class);
        mockedFrameworkServiceDataHolder = Mockito.mockStatic(FrameworkServiceDataHolder.class);
        mockedLoggerUtils = Mockito.mockStatic(LoggerUtils.class);
        
        mockUserStoreManager = mock(AbstractUserStoreManager.class);
        frameworkServiceDataHolder = mock(FrameworkServiceDataHolder.class);
        
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        mockedFrameworkUtils.when(() -> FrameworkUtils.getApplicationName(any())).thenReturn(Optional.of(DUMMY_APP_NAME));
        mockedFrameworkUtils.when(() -> FrameworkUtils.getApplicationResourceId(any())).thenReturn(Optional.of(DUMMY_APP_RESOURCE_ID));
    }

    @AfterMethod
    public void tearDown() throws Exception {
        // Close all static mocks.
        try {
            if (mockedTokenGenerator != null) {
                mockedTokenGenerator.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedIdentityUtil != null) {
                mockedIdentityUtil.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedIdentityTenantUtil != null) {
                mockedIdentityTenantUtil.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedFrameworkUtils != null) {
                mockedFrameworkUtils.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedMultitenantUtils != null) {
                mockedMultitenantUtils.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedMagicLinkAuthContextCache != null) {
                mockedMagicLinkAuthContextCache.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedServiceURLBuilder != null) {
                mockedServiceURLBuilder.close();
                mockedServiceURLBuilder = null;
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedConfigurationFacade != null) {
                mockedConfigurationFacade.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedUserCoreUtil != null) {
                mockedUserCoreUtil.close();
                mockedUserCoreUtil = null;
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedFrameworkServiceDataHolder != null) {
                mockedFrameworkServiceDataHolder.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (mockedLoggerUtils != null) {
                mockedLoggerUtils.close();
            }
        } catch (Exception ignored) {}
        
        try {
            if (closeable != null) {
                closeable.close();
            }
        } catch (Exception ignored) {}
    }

    private void mockServiceURLBuilder() {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn(DEFAULT_SERVER_URL + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        if (mockedServiceURLBuilder != null) {
            mockedServiceURLBuilder.close();
        }
        mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class);
        mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(builder);
    }

    @DataProvider
    public Object[][] getCanHandleData() {

        return new Object[][] {
                { DUMMY_MAGIC_TOKEN, true },
                { null, false }
        };
    }

    @Test(description = "Test case for canHandle() method magic link flow.", dataProvider = "getCanHandleData")
    public void testCanHandle(String magicToken, boolean canHandle) throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(magicToken);
        Assert.assertEquals(magicLinkAuthenticator.canHandle(httpServletRequest), canHandle);
    }

    @DataProvider
    public Object[][] getCanHandleDataIdf() {

        return new Object[][] {
                { USERNAME, true },
                { null, false }
        };
    }

    @Test(description = "Test case for canHandle() method identifier first flow.", dataProvider = "getCanHandleDataIdf")
    public void testCanHandleIdfFlow(String username, boolean canHandle) {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.USER_NAME)).thenReturn(username);
        Assert.assertEquals(magicLinkAuthenticator.canHandle(httpServletRequest), canHandle);
    }

    @Test(description = "Test case for getFriendlyName() method.")
    public void testGetFriendlyName() {

        Assert.assertEquals(magicLinkAuthenticator.getFriendlyName(),
                MagicLinkAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for getName() method.")
    public void testGetName() {

        Assert.assertEquals(magicLinkAuthenticator.getName(), MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @DataProvider
    public Object[][] getInitiateAuthenticationRequestExceptionData() {

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        String sessionDataKey = UUID.randomUUID().toString();
        magicLinkAuthContextData.setSessionDataKey(sessionDataKey);
        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(DUMMY_MAGIC_TOKEN);
        MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);

        return new Object[][] {
                { cacheKey, cacheEntry, sessionDataKey },
                { cacheKey, null, null }
        };
    }

    @Test(description = "Test case for getContextIdentifier() method.",
            dataProvider = "getInitiateAuthenticationRequestExceptionData")
    public void testGetContextIdentifier(Object cacheKey, Object cacheEntry, String sessionDataKey) {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(
                DUMMY_MAGIC_TOKEN);
        mockedMagicLinkAuthContextCache.when(MagicLinkAuthContextCache::getInstance).thenReturn(mockMagicLinkAuthContextCache);

        when(mockMagicLinkAuthContextCache.getValueFromCache((MagicLinkAuthContextCacheKey) cacheKey)).thenReturn(
                (MagicLinkAuthContextCacheEntry) cacheEntry);
        assertEquals(magicLinkAuthenticator.getContextIdentifier(httpServletRequest), sessionDataKey);
    }

    @Test(description = "Test case for processAuthenticationResponse() method.")
    public void testProcessAuthenticationResponse() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(
                DUMMY_MAGIC_TOKEN);
        mockedMagicLinkAuthContextCache.when(MagicLinkAuthContextCache::getInstance).thenReturn(mockMagicLinkAuthContextCache);

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        magicLinkAuthContextData.setMagicToken(DUMMY_MAGIC_TOKEN);
        magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis());
        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(SUPER_TENANT_DOMAIN);
        magicLinkAuthContextData.setUser(user);
        magicLinkAuthContextData.setSessionDataKey(UUID.randomUUID().toString());

        MagicLinkServiceDataHolder.getInstance().setAccountLockService(mockAccountLockService);

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(DUMMY_MAGIC_TOKEN);
        MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);

        when(mockMagicLinkAuthContextCache.getValueFromCache(cacheKey)).thenReturn(cacheEntry);
        magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertNotNull(context.getSubject());
    }

    @Test(description = "Test case for processAuthenticationResponse() method.")
    public void testProcessAuthenticationResponseWithInvalidToken() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(
                DUMMY_MAGIC_TOKEN);
        mockedMagicLinkAuthContextCache.when(MagicLinkAuthContextCache::getInstance).thenReturn(mockMagicLinkAuthContextCache);

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        magicLinkAuthContextData.setMagicToken(DUMMY_MAGIC_TOKEN);
        // Setting created timestamp 10 minutes earlier.
        magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(600));
        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(SUPER_TENANT_DOMAIN);
        magicLinkAuthContextData.setUser(user);
        magicLinkAuthContextData.setSessionDataKey(UUID.randomUUID().toString());

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(DUMMY_MAGIC_TOKEN);
        MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);

        when(mockMagicLinkAuthContextCache.getValueFromCache(cacheKey)).thenReturn(cacheEntry);
        assertThrows(InvalidCredentialsException.class,
                () -> magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse,
                        context));
    }

    @Test(description = "Test case for processAuthenticationResponse() method.")
    public void testProcessAuthenticationResponseWithInvalidCredentialsException() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(null);
        assertThrows(InvalidCredentialsException.class,
                () -> magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse,
                        context));
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method magic link flow.")
    public void testInitiateAuthenticationRequest() throws Exception {

        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(SUPER_TENANT_ID);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        context.setTenantDomain(SUPER_TENANT_DOMAIN);
        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);

        mockedTokenGenerator.when(() -> TokenGenerator.generateToken(anyInt())).thenReturn(DUMMY_MAGIC_TOKEN);
        mockedMagicLinkAuthContextCache.when(MagicLinkAuthContextCache::getInstance).thenReturn(mockMagicLinkAuthContextCache);

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        magicLinkAuthContextData.setMagicToken(DUMMY_MAGIC_TOKEN);
        magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis());
        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(SUPER_TENANT_DOMAIN);
        magicLinkAuthContextData.setUser(user);
        magicLinkAuthContextData.setSessionDataKey(UUID.randomUUID().toString());

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(DUMMY_MAGIC_TOKEN);
        MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);
        when(mockMagicLinkAuthContextCache.getValueFromCache(cacheKey)).thenReturn(cacheEntry);
        MagicLinkServiceDataHolder.getInstance().setIdentityEventService(mockIdentityEventService);

        mockServiceURLBuilder();
        List<User> userList = new ArrayList<>();
        userList.add(user);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(userList);

        doAnswer((Answer<Object>) invocation -> {
            redirect = (String) invocation.getArguments()[0];
            return null;
        }).when(httpServletResponse).sendRedirect(anyString());

        magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        assertEquals(redirect, DEFAULT_SERVER_URL + "/" + MagicLinkAuthenticatorConstants.MAGIC_LINK_NOTIFICATION_PAGE);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method magic link flow.")
    public void testInitiateAuthenticationRequestWithInvalidUser() throws Exception {

        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(SUPER_TENANT_ID);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                INVALID_USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(INVALID_USERNAME);
        context.setTenantDomain(SUPER_TENANT_DOMAIN);
        context.setProperty("username", INVALID_USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);

        mockServiceURLBuilder();
        List<User> userList = new ArrayList<>();
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getUserListWithID(USERNAME_CLAIM, INVALID_USERNAME, null)).thenReturn(userList);

        doAnswer((Answer<Object>) invocation -> {
            redirect = (String) invocation.getArguments()[0];
            return null;
        }).when(httpServletResponse).sendRedirect(anyString());

        magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        assertEquals(redirect, DEFAULT_SERVER_URL + "/" + MagicLinkAuthenticatorConstants.MAGIC_LINK_NOTIFICATION_PAGE);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method magic link flow.")
    public void testInitiateAuthenticationRequestWithIOException() throws Exception {

        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(SUPER_TENANT_ID);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                INVALID_USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(INVALID_USERNAME);
        context.setTenantDomain(SUPER_TENANT_DOMAIN);
        context.setProperty("username", INVALID_USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);

        mockServiceURLBuilder();
        List<User> userList = new ArrayList<>();
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getUserListWithID(USERNAME_CLAIM, INVALID_USERNAME, null))
                .thenReturn(userList);

        doThrow(new IOException()).when(httpServletResponse).sendRedirect(anyString());
        assertThrows(AuthenticationFailedException.class,
                () -> magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse,
                        context));
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method identifier first flow.")
    public void testInitiateAuthenticationRequestIdfFlow() throws Exception {

        when(context.getLastAuthenticatedUser()).thenReturn(null);
        try {
            if (mockedConfigurationFacade != null) {
                mockedConfigurationFacade.close();
            }
        } catch (Exception ignored) {}
        mockedConfigurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
        mockedConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
        when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
        when(context.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);
        doAnswer((Answer<Object>) invocation -> {
            redirect = (String) invocation.getArguments()[0];
            return null;
        }).when(httpServletResponse).sendRedirect(anyString());

        magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        assertEquals(redirect, DUMMY_LOGIN_PAGEURL + ("?" + DUMMY_QUERY_PARAMS)
                + MagicLinkAuthenticatorConstants.AUTHENTICATORS +
                MagicLinkAuthenticatorConstants.IDF_HANDLER_NAME + ":" +
                MagicLinkAuthenticatorConstants.LOCAL);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method identifier first flow.")
    public void testInitiateAuthenticationRequestIdfFlowWithIOException() throws Exception {

        when(context.getLastAuthenticatedUser()).thenReturn(null);
        try {
            if (mockedConfigurationFacade != null) {
                mockedConfigurationFacade.close();
            }
        } catch (Exception ignored) {}
        mockedConfigurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
        mockedConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
        when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
        when(context.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);

        doThrow(new IOException()).when(httpServletResponse).sendRedirect(anyString());
        assertThrows(AuthenticationFailedException.class,
                () -> magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse,
                        context));
    }

    @Test(description = "Test case for process() method identifier first flow")
    public void testProcess() throws Exception {

        context.setProperty(MagicLinkAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);
        mockedFrameworkUtils.when(() -> FrameworkUtils.preprocessUsername(USERNAME, context)).thenReturn(USERNAME_WITH_TENANT_DOMAIN);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(USERNAME)).thenReturn(SUPER_TENANT_DOMAIN);
        if (mockedUserCoreUtil != null) {
            mockedUserCoreUtil.close();
        }
        mockedUserCoreUtil = Mockito.mockStatic(UserCoreUtil.class);
        mockedUserCoreUtil.when(() -> UserCoreUtil.addTenantDomainToEntry(USERNAME, SUPER_TENANT_DOMAIN))
                .thenReturn(USERNAME_WITH_TENANT_DOMAIN);
        mockedFrameworkUtils.when(() -> FrameworkUtils.prependUserStoreDomainToName(USERNAME)).thenReturn(USERNAME_WITH_TENANT_DOMAIN);
        context.setTenantDomain(SUPER_TENANT_DOMAIN);

        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(SUPER_TENANT_ID);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USERNAME);
        authenticatedUser.setUserName(USERNAME);
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);
        mockedTokenGenerator.when(() -> TokenGenerator.generateToken(anyInt())).thenReturn(DUMMY_MAGIC_TOKEN);
        mockedMagicLinkAuthContextCache.when(MagicLinkAuthContextCache::getInstance).thenReturn(mockMagicLinkAuthContextCache);

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        magicLinkAuthContextData.setMagicToken(DUMMY_MAGIC_TOKEN);
        User user = new User(UUID.randomUUID().toString(), USERNAME, null);

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(DUMMY_MAGIC_TOKEN);
        MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);
        when(mockMagicLinkAuthContextCache.getValueFromCache(cacheKey)).thenReturn(cacheEntry);
        MagicLinkServiceDataHolder.getInstance().setIdentityEventService(mockIdentityEventService);

        mockServiceURLBuilder();
        List<User> userList = new ArrayList<>();
        userList.add(user);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(userList);
        mockedFrameworkServiceDataHolder.when(FrameworkServiceDataHolder::getInstance).thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(mockRealmService);

        Mockito.doNothing().when(httpServletResponse).sendRedirect(anyString());

        AuthenticatorFlowStatus status = magicLinkAuthenticator.process(httpServletRequest,
                httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = magicLinkAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() {

        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(context.getExternalIdP().getIdPName()).thenReturn(MagicLinkAuthenticatorConstants.LOCAL);
        when(context.getProperty(MagicLinkAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR))
                .thenReturn(Boolean.TRUE);

        Optional<AuthenticatorData> authenticatorData = magicLinkAuthenticator.getAuthInitiationData(context);
        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USER_NAME, DISPLAY_USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);


        Assert.assertEquals(authenticatorDataObj.getName(), MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME);
        Assert.assertEquals(authenticatorDataObj.getAuthParams().size(), authenticatorParamMetadataList.size(),
                "Size of lists should be equal.");
        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.USER_PROMPT, "Prompt Type should match.");
        for (int i = 0; i < authenticatorParamMetadataList.size(); i++) {
            AuthenticatorParamMetadata expectedParam = authenticatorParamMetadataList.get(i);
            AuthenticatorParamMetadata actualParam = authenticatorDataObj.getAuthParams().get(i);

            Assert.assertEquals(actualParam.getName(), expectedParam.getName(), "Parameter name should match.");
            Assert.assertEquals(actualParam.getType(), expectedParam.getType(), "Parameter type should match.");
            Assert.assertEquals(actualParam.getParamOrder(), expectedParam.getParamOrder(),
                    "Parameter order should match.");
            Assert.assertEquals(actualParam.isConfidential(), expectedParam.isConfidential(),
                    "Parameter confidential status should match.");
        }
    }


    @Test(description = "Test case for processAuthenticationResponse() method when the user account is locked.")
    public void testProcessAuthenticationResponseForLockedUser() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(
                DUMMY_MAGIC_TOKEN);
        mockedMagicLinkAuthContextCache.when(MagicLinkAuthContextCache::getInstance).thenReturn(mockMagicLinkAuthContextCache);

        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(USERNAME_WITH_TENANT_DOMAIN);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn(SUPER_TENANT_DOMAIN);

        MagicLinkAuthContextData magicLinkAuthContextData = new MagicLinkAuthContextData();
        magicLinkAuthContextData.setMagicToken(DUMMY_MAGIC_TOKEN);
        magicLinkAuthContextData.setCreatedTimestamp(System.currentTimeMillis());
        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(SUPER_TENANT_DOMAIN);
        user.setUserID(UUID.randomUUID().toString());
        magicLinkAuthContextData.setUser(user);
        magicLinkAuthContextData.setSessionDataKey(UUID.randomUUID().toString());

        MagicLinkServiceDataHolder.getInstance().setAccountLockService(mockAccountLockService);
        when(mockAccountLockService.isAccountLocked(
                USERNAME_WITH_TENANT_DOMAIN, SUPER_TENANT_DOMAIN, USER_STORE_DOMAIN)).thenReturn(true);

        MagicLinkAuthContextCacheKey cacheKey = new MagicLinkAuthContextCacheKey(DUMMY_MAGIC_TOKEN);
        MagicLinkAuthContextCacheEntry cacheEntry = new MagicLinkAuthContextCacheEntry(magicLinkAuthContextData);

        when(mockMagicLinkAuthContextCache.getValueFromCache(cacheKey)).thenReturn(cacheEntry);
        assertThrows(AuthenticationFailedException.class,
                () -> magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse,
                        context));
        assertTrue(magicLinkAuthenticator.retryAuthenticationEnabled());

        when(mockAccountLockService.isAccountLocked(anyString(), anyString(), anyString()))
                .thenThrow(new AccountLockServiceException("Error occurred while checking account lock status"));
        assertThrows(AuthenticationFailedException.class,
                () -> magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse,
                        context));
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when the user account is locked.")
    public void testInitiateAuthenticationRequestWithLockedUser() throws Exception {

        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(SUPER_TENANT_ID);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        context.setTenantDomain(SUPER_TENANT_DOMAIN);
        context.setProperty("username", INVALID_USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        context.setRetrying(true);
        context.setProperty(ACCOUNT_LOCKED, true);
        context.setCallerSessionKey(UUID.randomUUID().toString());
        context.setQueryParams(DUMMY_QUERY_PARAMS);
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(DUMMY_QUERY_PARAMS);
        when(FrameworkUtils.appendQueryParamsStringToUrl(DEFAULT_SERVER_URL + "/" + ERROR_PAGE,
                DUMMY_QUERY_PARAMS + ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS)).thenReturn(
                DEFAULT_SERVER_URL + "/" + ERROR_PAGE + "?" + DUMMY_QUERY_PARAMS +
                        ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS);

        mockServiceURLBuilder();
        List<User> userList = new ArrayList<>();
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getUserListWithID(USERNAME_CLAIM, INVALID_USERNAME, null)).thenReturn(userList);

        doAnswer((Answer<Object>) invocation -> {
            redirect = (String) invocation.getArguments()[0];
            return null;
        }).when(httpServletResponse).sendRedirect(anyString());

        magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        assertEquals(redirect, DEFAULT_SERVER_URL + "/" + ERROR_PAGE + "?" + DUMMY_QUERY_PARAMS +
                ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS);
        assertFalse(magicLinkAuthenticator.retryAuthenticationEnabled());
    }
}
