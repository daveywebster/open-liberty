/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.classloading.libdelegation.test.app;

import javax.servlet.annotation.WebServlet;

import org.junit.Test;

import com.ibm.ws.jca.cm.mbean.Tester;

import componenttest.app.FATServlet;
import io.openliberty.classloading.libs.util.CodeSourceUtil;

/**
 * TODO This is a placeholder test for now.  It doesn't actually assert anything.
 */
@WebServlet("/LibDelegationTestServlet")
public class LibDelegationTestServlet extends FATServlet{

    private static final long serialVersionUID = 1L;

    @Test
    public void testLoadAPIClassFromLibrary() throws ClassNotFoundException {
        System.out.println("TJW - App initiating = " + CodeSourceUtil.getClassCodeSourceFileName(Class.forName("com.ibm.ws.jca.cm.mbean.ConnectionManagerMBean")));
        System.out.println("TJW - Lib initiating = " + Tester.getCodeSource());
    }
}
