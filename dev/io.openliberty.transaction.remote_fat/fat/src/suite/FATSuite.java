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
package suite;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.transaction.fat.util.PostgresqlContainerSuite;

import componenttest.containers.SimpleLogConsumer;
import componenttest.rules.repeater.FeatureReplacementAction;
import componenttest.rules.repeater.RepeatTests;
import componenttest.topology.database.container.DatabaseContainerType;
import componenttest.topology.database.container.PostgreSQLContainer;
import componenttest.topology.impl.LibertyServer;
import tests.LocalEJBTest;
import tests.RemoteEJBTest;

@RunWith(Suite.class)
@SuiteClasses({
                LocalEJBTest.class,
                RemoteEJBTest.class,
})
public class FATSuite extends PostgresqlContainerSuite {

    //@ClassRule
    public static RepeatTests r = RepeatTests.withoutModification()
                    .andWith(FeatureReplacementAction.EE8_FEATURES())
                    .andWith(FeatureReplacementAction.EE9_FEATURES())
                    .andWith(FeatureReplacementAction.EE10_FEATURES());

    static {
        testContainer = new PostgreSQLContainer(getPostgresqlImageName())
                        .withDatabaseName(POSTGRES_DB)
                        .withUsername(POSTGRES_USER)
                        .withPassword(POSTGRES_PASS)
                        .withSSL()
                        .withLogConsumer(new SimpleLogConsumer(FATSuite.class, "postgre-ssl"));

        beforeSuite(DatabaseContainerType.Postgres);
    }

    public static void setUp(LibertyServer... servers) throws Exception {

        @SuppressWarnings("deprecation")
        String host = testContainer.getContainerIpAddress();
        String port = String.valueOf(testContainer.getMappedPort(5432));
        String jdbcURL = testContainer.getJdbcUrl() + "?user=" + POSTGRES_USER + "&password=" + POSTGRES_PASS;
        Log.info(FATSuite.class, "setUp", "Using PostgreSQL properties: host=" + host + "  port=" + port + ",  URL=" + jdbcURL);

        for (LibertyServer server : servers) {
            server.addEnvVar("POSTGRES_HOST", host);
            server.addEnvVar("POSTGRES_PORT", port);
            server.addEnvVar("POSTGRES_DB", POSTGRES_DB);
            server.addEnvVar("POSTGRES_USER", POSTGRES_USER);
            server.addEnvVar("POSTGRES_PASS", POSTGRES_PASS);
            server.addEnvVar("POSTGRES_URL", jdbcURL);
        }
    }
}
