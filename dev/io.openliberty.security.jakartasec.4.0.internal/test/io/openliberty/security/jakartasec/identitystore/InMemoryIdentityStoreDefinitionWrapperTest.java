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

import java.lang.annotation.Annotation;
import java.util.Arrays;

import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition.Credentials;

/**
 *
 */
public class InMemoryIdentityStoreDefinitionWrapperTest {
    /*** for testing ***/

    public static void main(String[] args) {

        class Cred implements Credentials {
            private final String callerName;
            private final String[] groups;
            private final String password;

            Cred(String callerName, String[] groups, String password) {
                this.callerName = callerName;
                this.groups = groups.clone();
                this.password = password;
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return null;
            }

            @Override
            public String callerName() {
                return callerName;
            }

            @Override
            public String[] groups() {
                return groups;
            }

            @Override
            public String password() {
                return password;
            }
        }

        Cred c1 = new Cred("dave", new String[] { "g1", "g2" }, "mypassword");
        Cred c2 = new Cred("sally", new String[] { "g3" }, "sallypassword");
        Cred c3 = new Cred("frank", new String[] {}, "frankpassword");
        Credentials[] creds_src = { c1, c2, c3 };
        Credentials[] creds_dest = creds_src.clone();
        System.out.println("creds_dest is: " + Arrays.toString(creds_dest));
    }

}
