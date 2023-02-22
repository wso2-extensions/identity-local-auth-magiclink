/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.magiclink.attribute.handler;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.magiclink.MagicLinkAuthenticatorConstants;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerBindingType;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerConstants;
import org.wso2.carbon.identity.auth.attribute.handler.model.AuthAttribute;
import org.wso2.carbon.identity.auth.attribute.handler.model.AuthAttributeHolder;
import org.wso2.carbon.identity.auth.attribute.handler.model.AuthAttributeType;
import org.wso2.carbon.identity.auth.attribute.handler.model.ValidationFailureReason;
import org.wso2.carbon.identity.auth.attribute.handler.model.ValidationResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerConstants.ErrorMessages.ERROR_CODE_ATTRIBUTE_NOT_FOUND;
import static org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerConstants.ErrorMessages.ERROR_CODE_ATTRIBUTE_VALUE_EMPTY;

/**
 * Test class for MagicLinkAuthAttributeHandler.
 */
public class MagicLinkAuthAttributeHandlerTest {

    private static final String HANDLER_NAME = "MagicLinkAuthAttributeHandler";
    private static final String ATTRIBUTE_USERNAME = "username";
    private static final String ATTRIBUTE_EMAIL = "http://wso2.org/claims/emailaddress";
    private static final String USERNAME_VALUE = "johndoe";
    private static final String EMAIL_VALUE = "johndoe@abc.com";
    private static final MagicLinkAuthAttributeHandler HANDLER = new MagicLinkAuthAttributeHandler();

    @Test
    public void testGetName() {

        Assert.assertEquals(HANDLER.getName(), HANDLER_NAME,
                "Did not receive the expected auth attribute handler name.");
    }

    @Test
    public void testGetBindingType() {

        Assert.assertEquals(HANDLER.getBindingType(), AuthAttributeHandlerBindingType.AUTHENTICATOR,
                "Did not receive the expected auth attribute binding type.");
    }

    @Test
    public void testGetBoundIdentifier() {

        Assert.assertEquals(HANDLER.getBoundIdentifier(), MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME,
                "Did not receive the expected bound identifier.");
    }

    @Test
    public void testGetAuthAttributeData() {

        AuthAttributeHolder holder = HANDLER.getAuthAttributeData();
        Assert.assertEquals(holder.getHandlerName(), HANDLER_NAME,
                "Did not receive the expected auth attribute handler name.");
        Assert.assertEquals(holder.getHandlerBinding(), AuthAttributeHandlerBindingType.AUTHENTICATOR,
                "Did not receive the expected auth attribute binding type.");
        Assert.assertEquals(holder.getHandlerBoundIdentifier(), MagicLinkAuthenticatorConstants.AUTHENTICATOR_NAME,
                "Did not receive the expected bound identifier.");
        Assert.assertEquals(holder.getProperties().size(), 0,
                "Holder properties should be empty but contains values.");
        Assert.assertEquals(holder.getAuthAttributes().size(), 2, "Unexpected number of auth attributes.");
        for (AuthAttribute authAttribute : holder.getAuthAttributes()) {
            AuthAttribute expectedAuthAttribute = getAuthAttribute(authAttribute.getAttribute());
            String attribute = authAttribute.getAttribute();

            Assert.assertNotNull(expectedAuthAttribute, String.format("Unexpected auth attribute %s available in " +
                    "the auth attribute list", attribute));
            Assert.assertEquals(authAttribute.isClaim(), expectedAuthAttribute.isClaim(),
                    "Expected value not found for isClaim field of the auth attribute: " + attribute);
            Assert.assertEquals(authAttribute.isConfidential(), expectedAuthAttribute.isConfidential(),
                    "Expected value not found for isConfidential field of the auth attribute: " + attribute);
            Assert.assertEquals(authAttribute.getType(), expectedAuthAttribute.getType(),
                    "Expected value not found for type field of the auth attribute: " + attribute);
            Assert.assertEquals(authAttribute.getProperties().size(), 0,
                    String.format("Auth attribute: %s properties should be empty but contains values.", attribute));
        }
    }

    @DataProvider
    public Object[][] getAttributesAndExpectedResult() {

        return new Object[][]{
                {buildAttributeMap(USERNAME_VALUE, EMAIL_VALUE), new ValidationResult(true)},
                {buildAttributeMap(USERNAME_VALUE, null, false),
                        buildFailedValidationResult(null, ERROR_CODE_ATTRIBUTE_NOT_FOUND)},
                {buildAttributeMap(USERNAME_VALUE, null),
                        buildFailedValidationResult(null, ERROR_CODE_ATTRIBUTE_VALUE_EMPTY)},
                {buildAttributeMap(USERNAME_VALUE, " "),
                        buildFailedValidationResult(null, ERROR_CODE_ATTRIBUTE_VALUE_EMPTY)},
                {buildAttributeMap(null, EMAIL_VALUE, false),
                        buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_NOT_FOUND, null)},
                {buildAttributeMap(null, EMAIL_VALUE),
                        buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_VALUE_EMPTY, null)},
                {buildAttributeMap(" ", USERNAME_VALUE),
                        buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_VALUE_EMPTY, null)},
                {buildAttributeMap(null, null, false),
                        buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_NOT_FOUND, ERROR_CODE_ATTRIBUTE_NOT_FOUND)},
                {buildAttributeMap("", ""), buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_VALUE_EMPTY,
                        ERROR_CODE_ATTRIBUTE_VALUE_EMPTY)},
                {MapUtils.EMPTY_MAP, buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_NOT_FOUND,
                        ERROR_CODE_ATTRIBUTE_NOT_FOUND)},
                {null, buildFailedValidationResult(ERROR_CODE_ATTRIBUTE_NOT_FOUND, ERROR_CODE_ATTRIBUTE_NOT_FOUND)},
        };
    }

    @Test(dataProvider = "getAttributesAndExpectedResult")
    public void testValidateAttributes(Object attributeMap, Object expectedResult) {

        ValidationResult expectedRes = (ValidationResult) expectedResult;
        try {
            ValidationResult validationResult = HANDLER.validateAttributes((Map<String, String>) attributeMap);

            if (validationResult.isValid() != expectedRes.isValid()) {
                Assert.fail(String.format("Expected isValid to be: %s actual isValid: %s", validationResult.isValid(),
                        expectedRes.isValid()));
            }

            if (!validationResult.isValid() &&
                    CollectionUtils.isEmpty(validationResult.getValidationFailureReasons())) {
                Assert.fail("validationFailureReasons should not be empty.");
            }

            if (validationResult.isValid() &&
                    CollectionUtils.isNotEmpty(validationResult.getValidationFailureReasons())) {
                Assert.fail("validationFailureReasons should be empty.");
            }

            if (!validationResult.isValid()) {
                // Check if expected failure reasons are not present.
                for (ValidationFailureReason eReason : expectedRes.getValidationFailureReasons()) {
                    boolean foundExpectedFailure = false;
                    for (ValidationFailureReason aReason : validationResult.getValidationFailureReasons()) {
                        if (eReason.getErrorCode().equals(aReason.getErrorCode()) &&
                                eReason.getAuthAttribute().equals(aReason.getAuthAttribute()) &&
                                eReason.getReason().equals(aReason.getReason())) {
                            foundExpectedFailure = true;
                        }
                    }
                    if (!foundExpectedFailure) {
                        Assert.fail(String.format("Expected errorCode: %s with reason: '%s' not found for attribute: " +
                                        "%s",
                                eReason.getErrorCode(), eReason.getReason(), eReason.getAuthAttribute()));
                    }
                }

                // Check if unexpected failure reasons are present.
                for (ValidationFailureReason aReason : validationResult.getValidationFailureReasons()) {
                    boolean foundUnexpectedFailure = true;
                    for (ValidationFailureReason eReason : expectedRes.getValidationFailureReasons()) {
                        if (aReason.getErrorCode().equals(eReason.getErrorCode()) &&
                                aReason.getAuthAttribute().equals(eReason.getAuthAttribute()) &&
                                aReason.getReason().equals(eReason.getReason())) {
                            foundUnexpectedFailure = false;
                        }
                    }
                    if (foundUnexpectedFailure) {
                        Assert.fail(String.format("Unexpected errorCode: %s with reason: '%s' found for attribute: %s",
                                aReason.getErrorCode(), aReason.getReason(), aReason.getAuthAttribute()));
                    }
                }
            }
        } catch (Exception e) {
            Assert.fail("Test threw an unexpected exception.", e);
        }
    }

    private AuthAttribute getAuthAttribute(String name) {

        List<AuthAttribute> authAttributes = getAuthAttributes();
        for (AuthAttribute authAttribute : authAttributes) {
            if (StringUtils.equals(authAttribute.getAttribute(), name)) {
                return authAttribute;
            }
        }
        return null;
    }

    private List<AuthAttribute> getAuthAttributes() {

        List<AuthAttribute> authAttributes = new ArrayList<>();

        authAttributes.add(buildAuthAttribute(ATTRIBUTE_USERNAME, false));
        authAttributes.add(buildAuthAttribute(ATTRIBUTE_EMAIL, true));

        return authAttributes;
    }

    private AuthAttribute buildAuthAttribute(String name, boolean isClaim) {

        return new AuthAttribute(name, isClaim, false, AuthAttributeType.STRING);
    }

    private Map<String, String> buildAttributeMap(String usernameVal, String emailVal, boolean addNullAttributes) {

        Map<String, String> attributeMap = new HashMap<>();
        if (usernameVal != null || addNullAttributes) {
            attributeMap.put(ATTRIBUTE_USERNAME, usernameVal);
        }
        if (emailVal != null || addNullAttributes) {
            attributeMap.put(ATTRIBUTE_EMAIL, emailVal);
        }

        return attributeMap;
    }

    private Map<String, String> buildAttributeMap(String usernameVal, String emailVal) {

        return buildAttributeMap(usernameVal, emailVal, true);
    }

    private ValidationResult buildFailedValidationResult(AuthAttributeHandlerConstants.ErrorMessages unError,
                                                         AuthAttributeHandlerConstants.ErrorMessages emailError) {

        ValidationResult validationResult = new ValidationResult(false);

        if (unError != null) {
            validationResult.getValidationFailureReasons().add(
                    new ValidationFailureReason(ATTRIBUTE_USERNAME, unError.getCode(), unError.getMessage()));
        }

        if (emailError != null) {
            validationResult.getValidationFailureReasons().add(
                    new ValidationFailureReason(ATTRIBUTE_EMAIL, emailError.getCode(), emailError.getMessage()));
        }

        return validationResult;
    }
}
