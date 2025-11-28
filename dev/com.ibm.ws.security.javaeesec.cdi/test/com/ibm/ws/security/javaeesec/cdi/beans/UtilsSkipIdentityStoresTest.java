/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.javaeesec.cdi.beans;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.security.auth.Subject;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for Utils.validateWithIdentityStore with skipIdentityStores functionality.
 */
public class UtilsSkipIdentityStoresTest {

    private final Mockery mockery = new JUnit4Mockery();
    private Utils utils;
    private IdentityStoreHandler identityStoreHandler;
    private Subject clientSubject;
    private UsernamePasswordCredential credential;
    private static final String REALM_NAME = "testRealm";

    @Before
    public void setUp() {
        utils = new Utils();
        identityStoreHandler = mockery.mock(IdentityStoreHandler.class);
        clientSubject = new Subject();
        credential = new UsernamePasswordCredential("testUser", "testPassword");
    }

    @After
    public void tearDown() {
        mockery.assertIsSatisfied();
    }

    /**
     * Normal operation: skipIdentityStores is false and valid credentials,
     * so return SUCCESS.
     */
    @Test
    public void testValidateWithIdentityStore_SkipIdentityStoresFalse_ValidCredentials() {
        final CredentialValidationResult validResult = new CredentialValidationResult("testUser");

        mockery.checking(new Expectations() {
            {
                oneOf(identityStoreHandler).validate(credential);
                will(returnValue(validResult));
            }
        });

        AuthenticationStatus status = utils.validateWithIdentityStore(REALM_NAME, clientSubject,
                                                                      credential, identityStoreHandler);

        assertEquals("Should return SUCCESS for valid credentials",
                     AuthenticationStatus.SUCCESS, status);
        assertNotNull("Client subject should be populated", clientSubject.getPrincipals());
    }

    /**
     * Normal operation: skipIdentityStores is false and invalid credentials,
     * so return NOT_DONE.
     */
    @Test
    public void testValidateWithIdentityStore_SkipIdentityStoresFalse_InvalidCredentials() {
        final CredentialValidationResult invalidResult = CredentialValidationResult.INVALID_RESULT;

        mockery.checking(new Expectations() {
            {
                oneOf(identityStoreHandler).validate(credential);
                will(returnValue(invalidResult));
            }
        });

        AuthenticationStatus status = utils.validateWithIdentityStore(REALM_NAME, clientSubject,
                                                                      credential, identityStoreHandler);

        assertEquals("Should return SEND_FAILURE for invalid credentials",
                     AuthenticationStatus.SEND_FAILURE, status);
    }

    /**
     * Normal operation: skipIdentityStores is false, so return NOT_DONE.
     */
    @Test
    public void testValidateWithIdentityStore_SkipIdentityStoresFalse_NotValidated() {
        final CredentialValidationResult notValidatedResult = CredentialValidationResult.NOT_VALIDATED_RESULT;

        mockery.checking(new Expectations() {
            {
                oneOf(identityStoreHandler).validate(credential);
                will(returnValue(notValidatedResult));
            }
        });

        AuthenticationStatus status = utils.validateWithIdentityStore(REALM_NAME, clientSubject,
                                                                      credential, identityStoreHandler);

        assertEquals("Should return NOT_DONE when not validated",
                     AuthenticationStatus.NOT_DONE, status);
    }

    /**
     * Test validateWithIdentityStore handles null identity store.
     */
    @Test(expected = NullPointerException.class)
    public void testValidateWithIdentityStore_NullHandler() {
        // will throw NullPointerException - look at the code!
        utils.validateWithIdentityStore(REALM_NAME, clientSubject, credential, null);
    }

    /**
     * Test null credential for validateWithIdentityStore.
     */
    @Test
    public void testValidateWithIdentityStore_NullCredential() {
        mockery.checking(new Expectations() {
            {
                oneOf(identityStoreHandler).validate(null);
                will(returnValue(CredentialValidationResult.INVALID_RESULT));
            }
        });

        AuthenticationStatus status = utils.validateWithIdentityStore(REALM_NAME, clientSubject,
                                                                      null, identityStoreHandler);

        assertEquals("Should return SEND_FAILURE for null credential",
                     AuthenticationStatus.SEND_FAILURE, status);
    }

    /**
     * Test empty "" realm name for validateWithIdentityStore.
     */
    @Test
    public void testValidateWithIdentityStore_EmptyRealmName() {
        final CredentialValidationResult validResult = new CredentialValidationResult("testUser");

        mockery.checking(new Expectations() {
            {
                oneOf(identityStoreHandler).validate(credential);
                will(returnValue(validResult));
            }
        });

        AuthenticationStatus status = utils.validateWithIdentityStore("", clientSubject,
                                                                      credential, identityStoreHandler);

        assertEquals("Should return SUCCESS even with empty realm name",
                     AuthenticationStatus.SUCCESS, status);
    }

    /**
     * Test null realm name for validateWithIdentityStore.
     */
    @Test
    public void testValidateWithIdentityStore_NullRealmName() {
        final CredentialValidationResult validResult = new CredentialValidationResult("testUser");

        mockery.checking(new Expectations() {
            {
                oneOf(identityStoreHandler).validate(credential);
                will(returnValue(validResult));
            }
        });

        AuthenticationStatus status = utils.validateWithIdentityStore(null, clientSubject,
                                                                      credential, identityStoreHandler);

        assertEquals("Should return SUCCESS even with null realm name",
                     AuthenticationStatus.SUCCESS, status);
    }
}
