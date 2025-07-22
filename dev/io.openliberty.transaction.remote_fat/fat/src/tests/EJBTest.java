/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package tests;

import com.ibm.ws.transaction.fat.util.SetupRunner;
import com.ibm.ws.transaction.fat.util.TxTestContainerSuite;

import componenttest.topology.database.container.DatabaseContainerType;
import componenttest.topology.database.container.DatabaseContainerUtil;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.utils.FATServletClient;

public class EJBTest extends FATServletClient {

    static SetupRunner runner = new SetupRunner() {
        @Override
        public void run(LibertyServer s) throws Exception {
            setUp(s);
        }
    };

    static void setUp(LibertyServer server) throws Exception {
        //Get driver name
        server.addEnvVar("DB_DRIVER", DatabaseContainerType.valueOf(TxTestContainerSuite.testContainer).getDriverName());

        //Setup server DataSource properties
        DatabaseContainerUtil.build(server, TxTestContainerSuite.testContainer).withDatabaseProperties().modify();
    }
}