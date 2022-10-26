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
package org.wso2.carbon.identity.application.authenticator.magiclink.internal;

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service Data Holder related to magic link authentication flow.
 */
public class MagicLinkServiceDataHolder {

    private static final MagicLinkServiceDataHolder MagicLinkServiceDataHolder = new MagicLinkServiceDataHolder();

    private IdentityEventService identityEventService;
    private RealmService realmService;
    private IdentityGovernanceService identityGovernanceService;
    private MultiAttributeLoginService multiAttributeLoginService;
    private OrganizationUserResidentResolverService organizationUserResidentResolverService;

    private MagicLinkServiceDataHolder() {

    }

    public static MagicLinkServiceDataHolder getInstance() {

        return MagicLinkServiceDataHolder;
    }

    public IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    public void setIdentityEventService(IdentityEventService identityEventService) {

        this.identityEventService = identityEventService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public MultiAttributeLoginService getMultiAttributeLoginService() {

        return multiAttributeLoginService;
    }

    public void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {
        this.multiAttributeLoginService = multiAttributeLoginService;
    }

    public OrganizationUserResidentResolverService getOrganizationUserResidentResolverService() {

        return organizationUserResidentResolverService;
    }

    public void setOrganizationUserResidentResolverService
            (OrganizationUserResidentResolverService organizationUserResidentResolverService) {
        this.organizationUserResidentResolverService = organizationUserResidentResolverService;
    }

    /**
     * Get Identity Governance Service.
     *
     * @return Identity Governance Service.
     */
    public IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    /**
     * Set Identity Governance Service.
     *
     * @param identityGovernanceService Identity Governance Service.
     */
    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        this.identityGovernanceService = identityGovernanceService;
    }
}

