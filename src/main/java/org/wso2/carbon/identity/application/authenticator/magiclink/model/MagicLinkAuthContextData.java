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

package org.wso2.carbon.identity.application.authenticator.magiclink.model;

import org.wso2.carbon.user.core.common.User;

import java.io.Serializable;

/**
 * MagicLink Authentication context data.
 */
public class MagicLinkAuthContextData implements Serializable {

    private static final long serialVersionUID = -7808710702471550901L;
    private String sessionDataKey;
    private User user;
    private String magicToken;
    private long createdTimestamp;

    public String getSessionDataKey() {

        return sessionDataKey;
    }

    public void setSessionDataKey(String sessionDataKey) {

        this.sessionDataKey = sessionDataKey;
    }

    public User getUser() {

        return user;
    }

    public void setUser(User user) {

        this.user = user;
    }

    public String getMagicToken() {

        return magicToken;
    }

    public void setMagicToken(String magicToken) {

        this.magicToken = magicToken;
    }

    public long getCreatedTimestamp() {

        return createdTimestamp;
    }

    public void setCreatedTimestamp(long createdTimestamp) {

        this.createdTimestamp = createdTimestamp;
    }
}
