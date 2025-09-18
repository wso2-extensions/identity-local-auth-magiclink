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

package org.wso2.carbon.identity.application.authenticator.magiclink.util;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.ERROR_PAGE;
import static org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;

/**
 * Utility functions for the authenticator.
 */
public class MagicLinkAuthUtils {

    /**
     * Check whether the account is locked.
     *
     * @param user AuthenticatedUser.
     * @return true if the account is locked.
     * @throws AuthenticationFailedException If an error occurred while checking the account lock status.
     */
    public static boolean isAccountLocked(AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            return MagicLinkServiceDataHolder.getInstance().getAccountLockService().isAccountLocked(
                    user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            String error = String.format(
                    MagicLinkAuthErrorConstants.ErrorMessages.ERROR_GETTING_ACCOUNT_LOCKED_STATE.getMessage(),
                    MagicLinkAuthUtils.maskUsernameIfRequired(user.getUserName()));
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages.ERROR_GETTING_ACCOUNT_LOCKED_STATE.getCode(), error, e);
        }
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskUsernameIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    /**
     * To redirect flow to the error page when the user account is locked.
     *
     * @param response The httpServletResponse.
     * @param context  The AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    public static void redirectToErrorPageForLockedUser(HttpServletResponse response,
                                                        AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            queryParams += ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;
            String errorPage = getErrorPageUrl();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(errorPage, queryParams);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE.getCode(),
                    MagicLinkAuthErrorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE.getMessage(),
                    e);
        }
    }

    /**
     * Get Magic Link error page URL.
     *
     * @return URL of the Magic Link error page.
     * @throws AuthenticationFailedException If an error occurred while getting the error page url.
     */
    public static String getErrorPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create().addPath(ERROR_PAGE).build(
                    IdentityUtil.getHostName()).getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error while building Magic Link error page URL", e);
        }
    }

}
