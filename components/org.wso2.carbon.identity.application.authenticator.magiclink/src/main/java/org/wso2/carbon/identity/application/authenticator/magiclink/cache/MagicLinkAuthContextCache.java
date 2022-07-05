/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.magiclink.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.authenticator.magiclink.model.MagicLinkAuthContextData;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

/**
 * Cache for {@link MagicLinkAuthContextData}
 */
public class MagicLinkAuthContextCache
        extends BaseCache<MagicLinkAuthContextCacheKey, MagicLinkAuthContextCacheEntry> {

    private static Log log = LogFactory.getLog(MagicLinkAuthContextCache.class);
    private static final String CACHE_NAME = "MagicLinkAuthContextCache";
    private static volatile MagicLinkAuthContextCache instance;

    private MagicLinkAuthContextCache() {

        super(CACHE_NAME);
    }

    public static MagicLinkAuthContextCache getInstance() {

        if (instance == null) {
            synchronized (MagicLinkAuthContextCache.class) {
                if (instance == null) {
                    instance = new MagicLinkAuthContextCache();
                }
            }
        }
        return instance;
    }

    @Override
    public void addToCache(MagicLinkAuthContextCacheKey key, MagicLinkAuthContextCacheEntry entry) {

        super.addToCache(key, entry);
        int tenantId;
        if (entry.getMagicLinkAuthContextData() != null && entry.getMagicLinkAuthContextData().getUser() != null) {
            String tenantDomain = entry.getMagicLinkAuthContextData().getUser().getTenantDomain();
            if (tenantDomain != null) {
                tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                SessionDataStore.getInstance().storeSessionData(key.getContextId(), CACHE_NAME, entry, tenantId);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Cache value corresponding to the key: " + key.getContextId() + " is added to the cache.");
        }
    }

    @Override
    public MagicLinkAuthContextCacheEntry getValueFromCache(MagicLinkAuthContextCacheKey key) {

        MagicLinkAuthContextCacheEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            cacheEntry = (MagicLinkAuthContextCacheEntry) SessionDataStore.getInstance()
                    .getSessionData(key.getContextId(), CACHE_NAME);
        }
        if (cacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache value corresponding to the key: " + key.getContextId() + " cannot be found.");
            }
        }
        return cacheEntry;
    }

    @Override
    public void clearCacheEntry(MagicLinkAuthContextCacheKey key) {

        super.clearCacheEntry(key);
        SessionDataStore.getInstance().clearSessionData(key.getContextId(), CACHE_NAME);
        if (log.isDebugEnabled()) {
            log.debug("Cache value corresponding to the key: " + key.getContextId() + " is cleared.");
        }
    }
}
