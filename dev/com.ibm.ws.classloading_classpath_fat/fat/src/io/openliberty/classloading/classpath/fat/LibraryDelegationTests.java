/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.classloading.classpath.fat;

import static io.openliberty.classloading.classpath.fat.FATSuite.LIB_DELEGATION_WAR_TEST_SERVER;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB1_JAR;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB_DELEGATION_APP;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB_DELEGATION_WAR;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.ShrinkHelper.DeployOptions;

import componenttest.annotation.Server;
import componenttest.annotation.TestServlet;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.utils.FATServletClient;
import io.openliberty.classloading.libdelegation.test.app.LibDelegationTestServlet;

/**
 * TODO This is a placeholder test for now.  It doesn't actually assert anything.
 */
@RunWith(FATRunner.class)
public class LibraryDelegationTests extends FATServletClient {

    @Server(LIB_DELEGATION_WAR_TEST_SERVER)
    @TestServlet(servlet = LibDelegationTestServlet.class, contextRoot = TEST_LIB_DELEGATION_APP)
    public static LibertyServer server;

    @Rule
    public TestName testName = new TestName();

    @BeforeClass
    public static void setupTestServer() throws Exception {
        ShrinkHelper.exportAppToServer(server, TEST_LIB_DELEGATION_WAR, DeployOptions.SERVER_ONLY);

        ShrinkHelper.exportToServer(server, "/libs", TEST_LIB1_JAR, DeployOptions.SERVER_ONLY);

        server.startServer();
    }

    @AfterClass
    public static void stopServer() throws Exception {
        server.stopServer();
    }
}
