/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.security.jakartasec.identitystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.ibm.websphere.ras.ProtectedString;

import io.openliberty.security.jakartasec.JakartaSec40Constants;
import io.openliberty.security.jakartasec.identitystore.InMemoryIdentityStoreDefinitionWrapper.CredentialValue;
import jakarta.security.enterprise.identitystore.IdentityStore.ValidationType;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition.Credentials;

/**
 * Unit tests for InMemoryIdentityStoreDefinitionWrapper
 */
public class InMemoryIdentityStoreDefinitionWrapperTest {

    // Test constants
    private static final String CALLER_NAME_1 = "testUser1";
    private static final String CALLER_NAME_2 = "testUser2";
    private static final String PASSWORD_1 = "password1";
    private static final String PASSWORD_2 = "password2";
    private static final String[] GROUPS_1 = { "group1", "group2" };
    private static final String[] GROUPS_2 = { "group3" };
    private static final int PRIORITY_VALUE = 100;
    private static final ValidationType[] USE_FOR_VALUES = { ValidationType.VALIDATE, ValidationType.PROVIDE_GROUPS };

    private TestInMemoryIdentityStoreDefinition testDefinition;
    private InMemoryIdentityStoreDefinitionWrapper wrapper;

    @Before
    public void setUp() {
        testDefinition = new TestInMemoryIdentityStoreDefinition();
        wrapper = new InMemoryIdentityStoreDefinitionWrapper(testDefinition);
    }

    /**
     * Test that constructor throws IllegalArgumentException when null definition is provided
     */
    @Test
    public void testConstructorWithNullDefinition() {
        try {
            new InMemoryIdentityStoreDefinitionWrapper(null);
            fail("Expected IllegalArgumentException was not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("The InMemoryIdentityStoreDefinition cannot be null.", e.getMessage());
        }
    }

    /**
     * Test getPriority returns the expected priority value
     */
    @Test
    public void testGetPriority() {
        assertEquals("Priority value should match the configured value",
                     PRIORITY_VALUE, wrapper.getPriority());
    }

    /**
     * Test getUseFor returns the expected ValidationType values
     */
    @Test
    public void testGetUseFor() {
        Set<ValidationType> expectedUseFor = new HashSet<>(Arrays.asList(USE_FOR_VALUES));
        assertEquals("UseFor values should match the configured values",
                     expectedUseFor, wrapper.getUseFor());
    }

    /**
     * Test getCredentials returns the expected credentials map
     */
    @Test
    public void testGetCredentials() {
        Map<String, CredentialValue> credentials = wrapper.getCredentials();

        assertNotNull("Credentials map should not be null", credentials);
        assertEquals("Credentials map should contain 2 entries", 2, credentials.size());
        assertTrue("Credentials map should contain entry for " + CALLER_NAME_1,
                   credentials.containsKey(CALLER_NAME_1));
        assertTrue("Credentials map should contain entry for " + CALLER_NAME_2,
                   credentials.containsKey(CALLER_NAME_2));

        // Test groups for first user
        String[] groups1 = credentials.get(CALLER_NAME_1).getGroups();
        assertEquals("Group count for " + CALLER_NAME_1 + " should match",
                     GROUPS_1.length, groups1.length);
        for (int i = 0; i < GROUPS_1.length; i++) {
            assertEquals("Group at index " + i + " for " + CALLER_NAME_1 + " should match",
                         GROUPS_1[i], groups1[i]);
        }

        // Test groups for second user
        String[] groups2 = credentials.get(CALLER_NAME_2).getGroups();
        assertEquals("Group count for " + CALLER_NAME_2 + " should match",
                     GROUPS_2.length, groups2.length);
        for (int i = 0; i < GROUPS_2.length; i++) {
            assertEquals("Group at index " + i + " for " + CALLER_NAME_2 + " should match",
                         GROUPS_2[i], groups2[i]);
        }
    }

    /**
     * Test toString method returns a string containing expected values
     */
    @Test
    public void testToString() {
        String toString = wrapper.toString();
        assertTrue("toString should contain priority value",
                   toString.contains("priority=" + PRIORITY_VALUE));
        assertTrue("toString should contain useFor information",
                   toString.contains("useFor="));
        assertTrue("toString should contain credentials information",
                   toString.contains("creds="));
    }

    /**
     * Test password validation using reflection to access private methods
     */
    @Test
    public void testPasswordValidation() throws Exception {
        Map<String, CredentialValue> credentials = wrapper.getCredentials();
        CredentialValue credValue = credentials.get(CALLER_NAME_1);

        // Use reflection to access the validate method in CredentialPassword class
        Method validateMethod = credValue.getClass().getSuperclass().getDeclaredMethod("validate", ProtectedString.class);
        validateMethod.setAccessible(true);

        // Test with correct password
        ProtectedString correctPassword = new ProtectedString(PASSWORD_1.toCharArray());
        Boolean result = (Boolean) validateMethod.invoke(credValue, correctPassword);
        assertTrue("Password validation should succeed with correct password", result);

        // Test with incorrect password
        ProtectedString incorrectPassword = new ProtectedString("wrongpassword".toCharArray());
        result = (Boolean) validateMethod.invoke(credValue, incorrectPassword);
        assertFalse("Password validation should fail with incorrect password", result);

        // Test with null password
        result = (Boolean) validateMethod.invoke(credValue, (Object) null);
        assertFalse("Password validation should fail with null password", result);

        // Test with empty password
        result = (Boolean) validateMethod.invoke(credValue, new ProtectedString("".toCharArray()));
        assertFalse("Password validation should fail with empty password", result);
    }

    /**
     * Test wrapper with empty credentials array
     */
    @Test
    public void testEmptyCredentials() {
        TestInMemoryIdentityStoreDefinition emptyDefinition = new TestInMemoryIdentityStoreDefinition() {
            @Override
            public Credentials[] value() {
                return new Credentials[0];
            }
        };

        InMemoryIdentityStoreDefinitionWrapper emptyWrapper = new InMemoryIdentityStoreDefinitionWrapper(emptyDefinition);
        Map<String, CredentialValue> credentials = emptyWrapper.getCredentials();

        assertNotNull("Credentials map should not be null even when empty", credentials);
        assertEquals("Credentials map should be empty", 0, credentials.size());
    }

    /**
     * Test default useFor values when not specified
     */
    @Test
    public void testDefaultUseFor() {
        TestInMemoryIdentityStoreDefinition defaultDefinition = new TestInMemoryIdentityStoreDefinition() {
            @Override
            public ValidationType[] useFor() {
                return new ValidationType[0];
            }

            @Override
            public String useForExpression() {
                return "";
            }
        };

        InMemoryIdentityStoreDefinitionWrapper defaultWrapper = new InMemoryIdentityStoreDefinitionWrapper(defaultDefinition);
        Set<ValidationType> useFor = defaultWrapper.getUseFor();

        assertNotNull("UseFor set should not be null", useFor);
        assertEquals("UseFor should contain default validation types",
                     JakartaSec40Constants.SPEC_DEFAULT_VALIDATION_TYPES, useFor);
    }

    /**
     * Test default priority when not specified
     */
    @Test
    public void testDefaultPriority() {
        TestInMemoryIdentityStoreDefinition defaultDefinition = new TestInMemoryIdentityStoreDefinition() {
            @Override
            public int priority() {
                return 90;
            }

            @Override
            public String priorityExpression() {
                return "";
            }
        };

        InMemoryIdentityStoreDefinitionWrapper defaultWrapper = new InMemoryIdentityStoreDefinitionWrapper(defaultDefinition);
        int priority = defaultWrapper.getPriority();

        assertEquals("Priority should be the default value",
                     JakartaSec40Constants.SPEC_DEFAULT_PRIORITY, priority);
    }

    /**
     * Test implementation of InMemoryIdentityStoreDefinition for testing
     */
    private class TestInMemoryIdentityStoreDefinition implements InMemoryIdentityStoreDefinition {
        @Override
        public Class<? extends Annotation> annotationType() {
            return InMemoryIdentityStoreDefinition.class;
        }

        @Override
        public Credentials[] value() {
            return new Credentials[] {
                                       new TestCredentials(CALLER_NAME_1, PASSWORD_1, GROUPS_1),
                                       new TestCredentials(CALLER_NAME_2, PASSWORD_2, GROUPS_2)
            };
        }

        @Override
        public int priority() {
            return PRIORITY_VALUE;
        }

        @Override
        public String priorityExpression() {
            return "";
        }

        @Override
        public ValidationType[] useFor() {
            return USE_FOR_VALUES;
        }

        @Override
        public String useForExpression() {
            return "";
        }
    }

    /**
     * Test implementation of Credentials for testing
     */
    private class TestCredentials implements Credentials {
        private final String callerName;
        private final String password;
        private final String[] groups;

        TestCredentials(String callerName, String password, String[] groups) {
            this.callerName = callerName;
            this.password = password;
            this.groups = groups;
        }

        @Override
        public Class<? extends Annotation> annotationType() {
            return Credentials.class;
        }

        @Override
        public String callerName() {
            return callerName;
        }

        @Override
        public String password() {
            return password;
        }

        @Override
        public String[] groups() {
            return groups;
        }
    }
}

// Made with Bob
