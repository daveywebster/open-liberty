/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.classloading.classpath.fat;

import static io.openliberty.classloading.classpath.fat.FATSuite.APP_PARENT_TEST_SERVER;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_PLATFORM_DELEGATION_APP;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;

import componenttest.annotation.Server;
import componenttest.annotation.TestServlet;
import componenttest.app.JavaInfo;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;
import io.openliberty.classloading.classpath.test.lib6.Lib6;
import io.openliberty.classloading.classpath.test.lib7.Lib7;
import io.openliberty.classloading.classpath.test.lib8.Lib8;
import io.openliberty.classloading.classpath.test.lib9.Lib9;
import io.openliberty.classloading.platform.delegation.test.app.PlatformDelegationTestServlet;

/**
 *
 */
@RunWith(FATRunner.class)
public class AppParentDelegationPlatformNullPackagesTest extends AppParentDelegationAbstractTest {

    @Server(APP_PARENT_TEST_SERVER)
    @TestServlet(servlet = PlatformDelegationTestServlet.class, contextRoot = TEST_PLATFORM_DELEGATION_APP)
    public static LibertyServer server;

    @BeforeClass
    public static void setupTestServer() throws Exception {
        setAppParent(server, CONFIG_APP_PARENT_PLATFORM, null);
        setupTestServer(server);
    }

    @After
    public void checkTestTrace() throws Exception {
        String testMethodName = testName.getMethodName();
        testMethodName = testMethodName.substring(PlatformDelegationTestServlet.class.getSimpleName().length() + 1);
        checkTestTracePlatformNullPackages(testMethodName);
    }

    static void checkTestTracePlatformNullPackages(String testMethodName) throws Exception {
        String targetName = null;
        String traceMsg = null;
        String secondaryName = null;
        String secondaryMsg = null;
        switch (testMethodName) {
            case "testLoadLibrary6Class":
                targetName = Lib6.class.getName();
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? LOAD_CLASS_FILTERED_MSG : LOAD_CLASS_NOT_FILTERED_MSG;
                break;
            case "testLoadLibrary7Class":
                targetName = Lib7.class.getName();
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? LOAD_CLASS_FILTERED_MSG : LOAD_CLASS_NOT_FILTERED_MSG;
                break;
            case "testLoadLibrary8Class":
                targetName = Lib8.class.getName();
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? LOAD_CLASS_FILTERED_MSG : LOAD_CLASS_NOT_FILTERED_MSG;
                break;
            case "testLoadLibrary9Class":
                targetName = Lib9.class.getName();
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? LOAD_CLASS_FILTERED_MSG : LOAD_CLASS_NOT_FILTERED_MSG;
                break;
            case "testGetCommonResource":
                targetName = "io/openliberty/classloading/test/resources/common.properties";
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? FIND_RESOURCE_FILTERED_MSG : FIND_RESOURCE_NOT_FILTERED_MSG;
                break;
            case "testGetCommonResourcesOrder":
                targetName = "io/openliberty/classloading/test/resources/common.properties";
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? FIND_RESOURCES_FILTERED_MSG : FIND_RESOURCES_NOT_FILTERED_MSG;
                break;
            case "testGetPlatformResource":
                targetName = "java/lang/platform-delegation-test.txt";
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? FIND_RESOURCE_FILTERED_MSG : FIND_RESOURCE_NOT_FILTERED_MSG;
                break;
            case "testGetPlatformResources":
                targetName = "java/lang/platform-delegation-test.txt";
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? FIND_RESOURCES_FILTERED_MSG : FIND_RESOURCES_NOT_FILTERED_MSG;
                break;
            case "testLoadPlatformClass":
                targetName = "java.lang.PlatformDelegationTest";
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? LOAD_CLASS_FILTERED_MSG : LOAD_CLASS_NOT_FILTERED_MSG;
                break;
            case "testLoadKernelClass":
                targetName = "com.ibm.wsspi.kernel.embeddable.ServerBuilder";
                traceMsg = JavaInfo.JAVA_VERSION >= 9 ? LOAD_CLASS_FILTERED_MSG : LOAD_CLASS_NOT_FILTERED_MSG;
                // NOTE: on Java 8 we don't filter the class but
                // it should not be found when delegating to platform for all cases
                secondaryName = "CLASS NOT FOUND";
                secondaryMsg = "testLoadKernelClass:";
                break;
            case "testPlatformService":
                targetName = null;
                break;
            default:
               fail("Unknown test method: " + testMethodName);
        }
        if (targetName != null) {
            checkTrace(server, traceMsg, targetName);
        }
        if (secondaryName != null) {
            checkTrace(server, secondaryMsg, secondaryName);
        }
    }

    @AfterClass
    public static void stopServer() throws Exception {
        server.stopServer();
    }
}
