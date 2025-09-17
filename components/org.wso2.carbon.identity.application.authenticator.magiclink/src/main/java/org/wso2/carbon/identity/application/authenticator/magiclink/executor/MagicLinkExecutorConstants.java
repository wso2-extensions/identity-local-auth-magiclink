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

/**
 * Constants for the Magic Link executor.
 */
public class MagicLinkExecutorConstants {

    private MagicLinkExecutorConstants() {

    }

    public static final String MAGIC_LINK_EXECUTOR_CONTEXT = "magicLinkExecutorContextData";
    public static final String STATE_PARAM = "state";
    public static final String MAGIC_LINK_STATE_VALUE = "magicLinkStateValue";

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String MAGIC_LINK_AUTH_SERVICE = "local-auth-magiclink";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String SEND_MAGIC_LINK = "send-magiclink-token";
            public static final String PROCESS_MAGIC_LINK = "process-magiclink-token";
        }
    }

    public static class MagicLinkData {

        public static final String flowID  = "flowID";
        public static final String MAGIC_TOKEN= "magicToken";
        public static final String CREATED_TIMESTAMP = "createdTimestamp";

    }
}
