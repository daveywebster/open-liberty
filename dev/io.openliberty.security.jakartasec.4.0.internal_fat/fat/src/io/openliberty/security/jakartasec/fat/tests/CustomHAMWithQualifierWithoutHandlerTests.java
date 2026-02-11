/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package io.openliberty.security.jakartasec.fat.tests;

import static org.junit.Assert.assertEquals;

import java.net.HttpURLConnection;
import java.net.URL;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.ShrinkHelper.DeployOptions;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;
import multiple.ham.common.MultipleHAMProtectedResource;
import multiple.ham.custom.hams.CustomHAMWithQualifier;
import multiple.ham.custom.hams.CustomHAMWithQualifierTwo;
import multiple.ham.inbuilt.MultipleHAMQualifiersApplication;

/**
 * Tests appSecurity-6.0
 */
@RunWith(FATRunner.class)
@Mode(TestMode.LITE)
public class CustomHAMWithQualifierWithoutHandlerTests {

    public static final String SERVER_NAME = "jakartaSec40Server";
    public static final String APP_NAME = "MultipleHAMWithoutHandlerApp";
    private static final String CONTEXT_ROOT = "/" + APP_NAME;
    private static final String RESOURCE_PATH = "/resource/test";

    private static String url = null;

    @Server(SERVER_NAME)
    public static LibertyServer server;

    @BeforeClass
    public static void setUp() throws Exception {
        WebArchive multipleHamApp = ShrinkWrap.create(WebArchive.class,
                                                      APP_NAME + ".war").addClass(MultipleHAMQualifiersApplication.class).addClass(CustomHAMWithQualifier.class).addClass(CustomHAMWithQualifierTwo.class).addPackage("multiple.ham.common.qualifiers").addClass(MultipleHAMProtectedResource.class);

        // The URL is not expected to be modified during this test scope
        url = "http://localhost:" + server.getHttpDefaultPort() + CONTEXT_ROOT + RESOURCE_PATH;

        ShrinkHelper.exportDropinAppToServer(server, multipleHamApp, DeployOptions.SERVER_ONLY);

        server.startServer();
    }

    /*
     * Assert that we find the custom output messages in trace.log
     * indicating that all qualifier HAMs have been injected successfully in the Custom HAM Handler
     *
     */
    @Test
    public void testQualifiersInjectionCustomOutput() throws Exception {

        // Mark the trace before making HTTP connection
        server.setTraceMarkToEndOfDefaultTrace();

        URL urlObj = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();

        conn.setRequestMethod("GET");
        conn.setDoInput(true);
        int responseCode = conn.getResponseCode();
        assertEquals("Expected status code 200 but got " + responseCode, 200, responseCode);
    }

    /*
     * Assert that the custom HAM prioritization is printed as it is defined on the custom handler.
     * Since we explicitly prioritized the Admin qualifier on BasicHAM, that should be the expected output.
     *
     */
    @Test
    public void testCustomHAMQualifierPriorityOutput() throws Exception {

        // Mark the trace before making HTTP connection
        server.setTraceMarkToEndOfDefaultTrace();

        URL urlObj = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();

        conn.setRequestMethod("GET");
        conn.setDoInput(true);
        int responseCode = conn.getResponseCode();
        assertEquals("Expected status code 200 but got " + responseCode, 200, responseCode);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        server.stopServer();
    }

}
