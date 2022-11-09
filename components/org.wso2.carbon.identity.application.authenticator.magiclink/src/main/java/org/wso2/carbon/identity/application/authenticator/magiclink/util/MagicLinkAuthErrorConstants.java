package org.wso2.carbon.identity.application.authenticator.magiclink.util;

public class MagicLinkAuthErrorConstants {

    /**
     * Relevant error messages and error codes.
     * These error codes are commented as a group not because of the convention
     * but to maintain the togetherness of the errors.
     */
    public enum ErrorMessages {

        // Identifier related Error codes.
        EMPTY_USERNAME("BAS-60002", "Username is empty."),

        // IO related Error codes
        SYSTEM_ERROR_WHILE_AUTHENTICATING("BAS-65001", "System error while authenticating"),

        // Tenant related Error codes.
        INVALID_TENANT_ID_OF_THE_USER("BAS-65011",
                "Failed while trying to get the tenant ID of the user %s"),
        CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT("BAS-65012",
                "Cannot find the user realm for the given tenant: %s"),
        // UserStore related Exceptions.
        USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE("BAS-65021",
                "UserStoreException while trying to authenticate"),
        // Organization management exception while resolving user's resident org.
        ORGANIZATION_MGT_EXCEPTION_WHILE_TRYING_TO_RESOLVE_RESIDENT_ORG("BAS-65022",
                "Organization mgt exception while authenticating"),
        // UserStore Error codes.
        USER_DOES_NOT_EXISTS("17001", "User does not exists"),

        // User identification failure in organization hierarchy.
        USER_NOT_IDENTIFIED_IN_HIERARCHY("17003", "User is not identified");
        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s - %s", code, message);
        }
    }
}
