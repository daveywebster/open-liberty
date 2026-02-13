/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.classloading.platform.delegation.test.app;

import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB6;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB7;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB8;
import static io.openliberty.classloading.classpath.fat.FATSuite.TEST_LIB9;
import static io.openliberty.classloading.classpath.util.TestUtils.assertCommonResourceFromArchive;
import static io.openliberty.classloading.classpath.util.TestUtils.assertCommonResourceFromArchives;
import static io.openliberty.classloading.classpath.util.TestUtils.TEST_LOAD_RESULT.success_fromLIBLoader;

import java.io.IOException;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.List;
import java.util.ServiceLoader;

import javax.servlet.annotation.WebServlet;

import org.junit.Test;

import componenttest.app.FATServlet;
import io.openliberty.classloading.classpath.util.TestUtils.TEST_CLASS_LOAD;
import io.openliberty.classloading.classpath.util.TestUtils.TEST_LOAD_RESULT;

@WebServlet("/PlatformDelegationTestServlet")
public class PlatformDelegationTestServlet extends FATServlet{

    private static final long serialVersionUID = 1L;

    private void runTest(TEST_LOAD_RESULT expected) {
        TEST_CLASS_LOAD.valueOf(getTestMethod()).testLoadClass(expected, getClass());
    }

    @Test
    public void testLoadLibrary6Class() {
        runTest(success_fromLIBLoader);
    }

    @Test
    public void testLoadLibrary7Class() {
        runTest(success_fromLIBLoader);
    }

    @Test
    public void testLoadLibrary8Class() {
        runTest(success_fromLIBLoader);
    }

    @Test
    public void testLoadLibrary9Class() {
        runTest(success_fromLIBLoader);
    }

    @Test
    public void testGetCommonResourcesOrder() {
        List<String> expectedOrder = Arrays.asList(TEST_LIB6, //
                                                   TEST_LIB7, //
                                                   TEST_LIB8, //
                                                   TEST_LIB9);
        assertCommonResourceFromArchives(getClass(), expectedOrder);
    }

    @Test
    public void testGetCommonResource() {
        assertCommonResourceFromArchive(getClass(), TEST_LIB6);
    }

    @Test
    public void testLoadKernelClass() {
        try {
            Class.forName("com.ibm.wsspi.kernel.embeddable.ServerBuilder");
            System.out.println("testLoadKernelClass: CLASS FOUND");
        } catch (ClassNotFoundException e) {
            System.out.println("testLoadKernelClass: CLASS NOT FOUND");
        }
    }
    @Test
    public void testLoadPlatformClass() {
        // try to load a java.lang class that doesn't exist
        try {
            Class.forName("java.lang.PlatformDelegationTest");
        } catch (ClassNotFoundException e) {
            // expected
        }
    }

    @Test
    public void testGetPlatformResource() {
        // look for a resource from java/lang that doesn't exist
        getClass().getResource("/java/lang/platform-delegation-test.txt");
    }

    @Test
    public void testGetPlatformResources() throws IOException {
        // look for a resource from java/lang that doesn't exist
        getClass().getClassLoader().getResources("java/lang/platform-delegation-test.txt");
    }

    @Test
    public void testPlatformService() {
        doServiceLoaderCheck(FileSystemProvider.class);
    }

    /**
     * @param service
     */
    private void doServiceLoaderCheck(Class<?> serviceClass) {
        System.out.println("Testing platform service: " + serviceClass);
        ServiceLoader<?> serviceLoader = ServiceLoader.load(serviceClass);
        Object s = serviceLoader.iterator().next();
        System.out.println("Got platform service : " + s);
    }
}
