/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
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

import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCache;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheEntry;
import org.wso2.carbon.identity.application.authenticator.magiclink.cache.MagicLinkAuthContextCacheKey;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;

@PrepareForTest({ TokenGenerator.class, IdentityUtil.class, ServiceURLBuilder.class, IdentityTenantUtil.class,
        AbstractUserStoreManager.class, MagicLinkAuthContextCache.class })
@PowerMockIgnore({ "javax.net.*", "javax.security.*", "javax.crypto.*", "javax.xml.*" })
public class MagicLinkAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private final String USERNAME = "admin";
    private final String DUMMY_MAGIC_TOKEN = "Adafeaf23412vdasdfG6fshs";
    private MagicLinkAuthenticator magicLinkAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private UserRealm mockUserRealm;

    @Mock
    private AbstractUserStoreManager mockedUserStoreManager;

    @Mock
    private MagicLinkAuthContextCache magicLinkAuthContextCache;

    @BeforeMethod
    public void setUp() {

        magicLinkAuthenticator = new MagicLinkAuthenticator();
        initMocks(this);
        mockStatic(TokenGenerator.class);
        mockStatic(IdentityUtil.class);
        mockStatic(IdentityTenantUtil.class);
        mockedUserStoreManager = mock(AbstractUserStoreManager.class);
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
                PowerMockito.when(serviceURL.getAbsolutePublicURL()).thenReturn("http://localhost:9443" + path);
                PowerMockito.when(serviceURL.getRelativePublicURL()).thenReturn(path);
                PowerMockito.when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockStatic(ServiceURLBuilder.class);
        PowerMockito.when(ServiceURLBuilder.create()).thenReturn(builder);
    }

    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandle() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn("213432");
        Assert.assertEquals(magicLinkAuthenticator.canHandle(httpServletRequest), true);
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(null);
        Assert.assertEquals(magicLinkAuthenticator.canHandle(httpServletRequest), false);
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

    @Test(description = "Test case for retryAuthenticationEnabled() method.")
    public void testRetryAuthenticationEnabled() {

        Assert.assertEquals(magicLinkAuthenticator.retryAuthenticationEnabled(), false);
    }

    @Test(description = "Test case for processAuthenticationResponse() method.")
    public void testProcessAuthenticationResponse() throws Exception {

        when(httpServletRequest.getParameter(MagicLinkAuthenticatorConstants.MAGIC_LINK_TOKEN)).thenReturn(
                DUMMY_MAGIC_TOKEN);
        mockStatic(MagicLinkAuthContextCache.class);
        when(MagicLinkAuthContextCache.getInstance()).thenReturn(magicLinkAuthContextCache);

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

        when(magicLinkAuthContextCache.getValueFromCache(cacheKey)).thenReturn(cacheEntry);
        magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertNotNull(context.getSubject());
    }

    @Test(description = "Test case for processAuthenticationResponse() method.")
    public void testProcessAuthenticationResponseWithInvalidCredentialsException() throws Exception {

        try {
            magicLinkAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        } catch (AuthenticationFailedException e) {
            Assert.assertNotNull(e);
        }
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method.")
    public void testInitiateAuthenticationRequestWithAuthenticationFailedException() throws Exception {

        mockStatic(IdentityUtil.class);
        MagicLinkServiceDataHolder.getInstance().setRealmService(mockRealmService);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        when(IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(-1234);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                USERNAME);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(USERNAME);
        context.setTenantDomain(SUPER_TENANT_DOMAIN);
        context.setProperty("username", USERNAME);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);

        mockServiceURLBuilder();
        List<User> userList = new ArrayList<>();
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(userList);
        try {
            magicLinkAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        } catch (AuthenticationFailedException e) {
            Assert.assertNotNull(e);
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }
}
