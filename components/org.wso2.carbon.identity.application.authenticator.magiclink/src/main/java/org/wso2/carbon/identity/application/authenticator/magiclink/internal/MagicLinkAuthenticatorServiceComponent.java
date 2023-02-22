/*
 * Copyright (c) 2021, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.application.authenticator.magiclink.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticator;
import org.wso2.carbon.identity.application.authenticator.magiclink.attribute.handler.MagicLinkAuthAttributeHandler;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandler;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service component related to magic link authentication flow.
 */
@Component(
        name = "org.wso2.carbon.identity.application.authenticator.magiclink.component",
        immediate = true)
public class MagicLinkAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(MagicLinkAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            MagicLinkAuthenticator magicAuth = new MagicLinkAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), magicAuth, null);

            MagicLinkAuthAttributeHandler authAttributeHandler = new MagicLinkAuthAttributeHandler();
            ctxt.getBundleContext().registerService(AuthAttributeHandler.class.getName(), authAttributeHandler, null);
            if (log.isDebugEnabled()) {
                log.info("MagicLink Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("MagicLink Authenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("MagicLink Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        log.debug("Setting the Realm Service.");
        MagicLinkServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        MagicLinkServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "identity.governance.service",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        MagicLinkServiceDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        MagicLinkServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "identity.event.service",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        MagicLinkServiceDataHolder.getInstance().setIdentityEventService(eventService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        MagicLinkServiceDataHolder.getInstance().setIdentityEventService(null);
    }
}
