/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.webcontainer.security.internal;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.ibm.ws.security.SecurityService;
import com.ibm.wsspi.kernel.service.location.WsLocationAdmin;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;

/**
 * Unit tests for skipIdentityStores configuration in WebAppSecurityConfigImpl.
 */
public class WebAppSecurityConfigImplSkipIdentityStoresTest {

    private final Mockery mockery = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };
    private AtomicServiceReference<WsLocationAdmin> locationAdminRef;
    private AtomicServiceReference<SecurityService> securityServiceRef;

    @SuppressWarnings("unchecked")
    @Before
    public void setUp() {
        locationAdminRef = mockery.mock(AtomicServiceReference.class, "locationAdminRef");
        securityServiceRef = mockery.mock(AtomicServiceReference.class, "securityServiceRef");
    }

    @After
    public void tearDown() {
        mockery.assertIsSatisfied();
    }

    /**
     * Test returning false when not set.
     */
    @Test
    public void testSkipIdentityStores_NotConfigured_ReturnsFalse() {
        Map<String, Object> props = new HashMap<>();
        mockCookie(props, false);
        // skipIdentityStores not set in properties

        WebAppSecurityConfigImpl config = new WebAppSecurityConfigImpl(props, locationAdminRef, securityServiceRef, null, null);

        assertFalse("skipIdentityStores should default to false when not configured",
                    config.getSkipIdentityStores());
    }

    /**
     * Test returning false when explicitly set.
     */
    @Test
    public void testSkipIdentityStores_SetToFalse_ReturnsFalse() {
        Map<String, Object> props = new HashMap<>();
        mockCookie(props, false);
        props.put(WebAppSecurityConfigImpl.CFG_KEY_SKIP_IDENTITY_STORES, Boolean.FALSE);

        WebAppSecurityConfigImpl config = new WebAppSecurityConfigImpl(props, locationAdminRef, securityServiceRef, null, null);

        assertFalse("skipIdentityStores should return false when set to false",
                    config.getSkipIdentityStores());
    }

    /**
     * Test returning true when explicitly set.
     */
    @Test
    public void testSkipIdentityStores_SetToTrue_ReturnsTrue() {
        Map<String, Object> props = new HashMap<>();
        mockCookie(props, false);
        props.put(WebAppSecurityConfigImpl.CFG_KEY_SKIP_IDENTITY_STORES, Boolean.TRUE);

        WebAppSecurityConfigImpl config = new WebAppSecurityConfigImpl(props, locationAdminRef, securityServiceRef, null, null);

        assertTrue("skipIdentityStores should return true when set to true",
                   config.getSkipIdentityStores());
    }

    /**
     * Test correct default value for skipIdentityStores.
     */
    @Test
    public void testSkipIdentityStores_SetToNull_ReturnsFalse() {
        Map<String, Object> props = new HashMap<>();
        mockCookie(props, false);
        props.put(WebAppSecurityConfigImpl.CFG_KEY_SKIP_IDENTITY_STORES, null);

        WebAppSecurityConfigImpl config = new WebAppSecurityConfigImpl(props, locationAdminRef, securityServiceRef, null, null);

        assertFalse("skipIdentityStores should return false when set to null",
                    config.getSkipIdentityStores());
    }

    /**
     * Test configAttributes update.
     */
    @Test
    public void testSkipIdentityStores_IncludedInConfigAttributes() {
        assertTrue("CFG_KEY_SKIP_IDENTITY_STORES should be in configAttributes map",
                   WebAppSecurityConfigImpl.configAttributes.containsKey(WebAppSecurityConfigImpl.CFG_KEY_SKIP_IDENTITY_STORES));
    }

    /**
     * Test correct mapping.
     */
    @Test
    public void testSkipIdentityStores_ConfigAttributesMapping() {
        String mappedValue = WebAppSecurityConfigImpl.configAttributes.get(WebAppSecurityConfigImpl.CFG_KEY_SKIP_IDENTITY_STORES);

        assertTrue("skipIdentityStores should map to 'skipIdentityStores' in configAttributes",
                   "skipIdentityStores".equals(mappedValue));
    }

    /**
     * set up SSO cookie configuration to avoid IllegalArgumentException in constructor.
     */
    private void mockCookie(Map<String, Object> cfg, Boolean autoGenCookieName) {
        if (!autoGenCookieName) {
            cfg.put("ssoCookieName", "webSSOCookie");
        }
        cfg.put("autoGenSsoCookieName", autoGenCookieName);
    }
}
