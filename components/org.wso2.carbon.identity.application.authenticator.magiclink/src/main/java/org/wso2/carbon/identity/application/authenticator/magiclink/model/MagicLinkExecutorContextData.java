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

package org.wso2.carbon.identity.application.authenticator.magiclink.model;

import java.io.Serializable;

/**
 * Magic Link flow context data.
 */
public class MagicLinkExecutorContextData implements Serializable {

    private String flowID;
    private String magicToken;
    private long createdTimestamp;

    public String getFlowID() {

        return flowID;
    }

    public void setFlowID(String flowID) {

        this.flowID = flowID;
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
