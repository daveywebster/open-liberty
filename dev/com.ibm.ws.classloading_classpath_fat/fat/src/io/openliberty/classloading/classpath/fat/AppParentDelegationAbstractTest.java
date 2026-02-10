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
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB6_JAR;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB7_JAR;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB8_JAR;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB9_JAR;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_PLATFORM_DELEGATION_WAR;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.jboss.shrinkwrap.api.spec.JavaArchive;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.ShrinkHelper.DeployOptions;

import componenttest.topology.impl.LibertyFileManager;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.utils.FATServletClient;

public abstract class AppParentDelegationAbstractTest extends FATServletClient {
    public static final String CONFIG_APP_PARENT_PROP = "io.openliberty.classloading.app.parent";
    public static final String CONFIG_APP_PARENT_PACKAGES_PROP = "io.openliberty.classloading.app.parent.packages";
    public static final String CONFIG_APP_PARENT_SYSTEM = "SYSTEM";
    public static final String CONFIG_APP_PARENT_PLATFORM = "PLATFORM";

    public static final String LOAD_CLASS_FILTERED_MSG = "loadClass: filtered class load from gateway parent: ";
    public static final String LOAD_CLASS_NOT_FILTERED_MSG = "loadClass: loading class from gateway parent: ";
    public static final String FIND_RESOURCE_FILTERED_MSG = "getResource: filtered get resource from gateway parent: ";
    public static final String FIND_RESOURCE_NOT_FILTERED_MSG = "getResource: getting resource from gateway parent: ";
    public static final String FIND_RESOURCES_FILTERED_MSG = "getResources: filtered get resources from gateway parent: ";
    public static final String FIND_RESOURCES_NOT_FILTERED_MSG ="getResources: getting resources from gateway parent: ";

    public static void setAppParent(LibertyServer server, String parent, String packages) throws Exception {
        Map<String, String> bootstrapProps = new HashMap<>();
        if (parent != null) {
            bootstrapProps.put(CONFIG_APP_PARENT_PROP, parent);
        }
        if (packages != null) {
            bootstrapProps.put(CONFIG_APP_PARENT_PACKAGES_PROP, packages);
        }
        if (parent != null || packages != null) {
            server.addBootstrapProperties(bootstrapProps);
            Map<String, String> jvmOptions = server.getJvmOptionsAsMap();
            jvmOptions.put("-Dcom.ibm.ws.beta.edition", "true");
            server.setJvmOptions(jvmOptions);
        }
    }

    public static void setupTestServer(LibertyServer server) throws Exception {
        ShrinkHelper.exportAppToServer(server, TEST_PLATFORM_DELEGATION_WAR, DeployOptions.SERVER_ONLY);

        ShrinkHelper.exportToServer(server, "/libs", TEST_LIB6_JAR, DeployOptions.SERVER_ONLY);
        ShrinkHelper.exportToServer(server, "/libs", TEST_LIB7_JAR, DeployOptions.SERVER_ONLY);
        setupLibraryFolder(TEST_LIB8_JAR, server);
        setupLibraryFolder(TEST_LIB9_JAR, server);

        server.startServer();
    }

    private static void setupLibraryFolder(JavaArchive library, LibertyServer server) throws Exception {
        ShrinkHelper.exportArtifact(library, "publish/libs", true, false, true);
        String libJarName = library.getName();
        LibertyFileManager.copyFileIntoLiberty(server.getMachine(), server.getInstallRoot() + "/usr/servers/" + APP_PARENT_TEST_SERVER + "/libs",
                                               libJarName.substring(0, libJarName.length() - 4),
                                               "publish/libs/" + libJarName, true, server.getServerRoot());
    }

    public static void checkTrace(LibertyServer server, String expectedTraceMsg, String expectedTarget) throws Exception {
        Iterator<String> traceLines = server.findStringsInLogsAndTrace(".*").iterator();
        while (traceLines.hasNext()) {
            String line = traceLines.next();
            if (line.contains(expectedTraceMsg) && line.contains(expectedTarget)) {
                return;
            }
        }
        fail("Did not find the expected trace message '" + expectedTraceMsg + "' for target: " + expectedTarget);
    }
}
