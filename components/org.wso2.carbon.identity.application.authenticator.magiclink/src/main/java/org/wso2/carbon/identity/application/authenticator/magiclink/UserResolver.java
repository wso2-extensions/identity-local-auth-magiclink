package org.wso2.carbon.identity.application.authenticator.magiclink;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authenticator.magiclink.internal.MagicLinkServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.magiclink.util.MagicLinkAuthErrorConstants;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Optional;

/**
 * UserResolver class is responsible for resolving the user.
 * <p>
 * UserResolver resolves the user from:
 * <ul>
 * <li>Multi Attribute Login
 * <li>Organization Hierarchy
 * <li>User Store
 * </ul>
 * <p>
 * and returns the User object.
 */
public class UserResolver {

    public static Optional<User> resolveUserFromMultiAttributeLogin(AuthenticationContext context, String username)
            throws InvalidCredentialsException {

        if (MagicLinkServiceDataHolder.getInstance().getMultiAttributeLoginService()
                .isEnabled(context.getTenantDomain())) {
            ResolvedUserResult resolvedUserResult = MagicLinkServiceDataHolder.getInstance()
                    .getMultiAttributeLoginService()
                    .resolveUser(MultitenantUtils.getTenantAwareUsername(username), context.getTenantDomain());
            if (resolvedUserResult != null && ResolvedUserResult.UserResolvedStatus.SUCCESS.
                    equals(resolvedUserResult.getResolvedStatus())) {
                return Optional.of(resolvedUserResult.getUser());
            }
            throw new InvalidCredentialsException(
                    MagicLinkAuthErrorConstants.ErrorMessages.USER_DOES_NOT_EXISTS.getCode(),
                    MagicLinkAuthErrorConstants.ErrorMessages.USER_DOES_NOT_EXISTS.getMessage(),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username));
        }
        return Optional.empty();
    }

    public static Optional<User> resolveUserFromOrganizationHierarchy(AuthenticationContext context,
                                                                  String tenantAwareUsername, String username)
            throws AuthenticationFailedException {

        if (!canResolveUserFromOrganizationHierarchy(context)) {
            return Optional.empty();
        }
        String requestTenantDomain = context.getUserTenantDomain();
        try {
            int tenantId = IdentityTenantUtil.getTenantId(requestTenantDomain);
            Tenant tenant = (Tenant) MagicLinkServiceDataHolder.getInstance().getRealmService().getTenantManager()
                            .getTenant(tenantId);
            if (tenant != null && StringUtils.isNotBlank(tenant.getAssociatedOrganizationUUID())) {
                User user = MagicLinkServiceDataHolder.getInstance()
                        .getOrganizationUserResidentResolverService()
                        .resolveUserFromResidentOrganization(tenantAwareUsername, null,
                                tenant.getAssociatedOrganizationUUID())
                        .orElseThrow(() -> new AuthenticationFailedException(
                                MagicLinkAuthErrorConstants.ErrorMessages.USER_NOT_IDENTIFIED_IN_HIERARCHY.getCode()));
                return Optional.of(user);
            }
        } catch (OrganizationManagementException e) {
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages
                            .ORGANIZATION_MGT_EXCEPTION_WHILE_TRYING_TO_RESOLVE_RESIDENT_ORG.getCode(), e.getMessage(),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username), e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages
                            .USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(), e.getMessage(),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username), e);
        }
        return Optional.empty();
    }

    private static boolean canResolveUserFromOrganizationHierarchy(AuthenticationContext context) {

        if (context.getCallerPath() != null && context.getCallerPath().startsWith("/t/")) {
            return true;
        }
        String requestTenantDomain = context.getUserTenantDomain();
        return StringUtils.isNotBlank(requestTenantDomain) &&
                !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(requestTenantDomain);
    }

    public static Optional<User> resolveUserFromUserStore(String tenantDomain,
                                                          String tenantAwareUsername, String username)
            throws AuthenticationFailedException {

        AbstractUserStoreManager userStoreManager;

        try {
            int tenantId = MagicLinkServiceDataHolder.getInstance()
                    .getRealmService().getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = MagicLinkServiceDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
                String userId = userStoreManager.getUserIDFromUserName(tenantAwareUsername);
                User user = userStoreManager.getUser(userId, username);
                return Optional.ofNullable(user);
            }
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages
                            .CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getCode(), String.format(
                    MagicLinkAuthErrorConstants.ErrorMessages
                            .CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getMessage(), tenantId),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username));
        } catch (IdentityRuntimeException e) {
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages.INVALID_TENANT_ID_OF_THE_USER.getCode(),
                    e.getMessage(),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException(
                    MagicLinkAuthErrorConstants.ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE
                            .getCode(), e.getMessage(),
                    org.wso2.carbon.identity.application.common.model.User.getUserFromUserName(username), e);
        }
    }
}
