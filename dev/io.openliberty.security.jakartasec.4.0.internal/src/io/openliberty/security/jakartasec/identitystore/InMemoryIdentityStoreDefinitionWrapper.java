/*******************************************************************************
 * Copyright (c) 2017, 2025 IBM Corporation and others.
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
package io.openliberty.security.jakartasec.identitystore;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import com.ibm.websphere.ras.ProtectedString;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.javaeesec.identitystore.ELHelper;

import io.openliberty.security.jakartasec.JakartaSec40Constants;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStore.ValidationType;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition.Credentials;

/**
 * A wrapper class that offers convenience methods for retrieving configuration
 * from an {@link InMemoryIdentityStoreDefinition} instance.
 *
 * <p/>
 * The methods in this class will evaluate any EL expressions provided in the
 * {@link InMemoryIdentityStoreDefinition} first and if no EL expressions are provided,
 * return the literal value instead.
 *
 * As a reminder, here is an example of an in memory identity store annotation:
 *
 * @InMemoryIdentityStoreDefinition(
 * priority = 10,
 * priorityExpression = "#{80/20}",
 * useFor = {VALIDATE, PROVIDE_GROUPS},
 * useForExpression = "#{'VALIDATE'}",
 * value = {
 *
 * @Credentials(callerName = "bill", password = "secret1", groups = { "foo", "bar" }),
 * @Credentials(callerName = "sally", password = "secret1", groups = { "user" }),
 * @Credentials(callerName = "dave", password = "secret1", groups = { "caller", "user", "foo", "bar" })
 *                         })
 */

public class InMemoryIdentityStoreDefinitionWrapper {

    // TODO: evaluate password: support both expression and literal value, see evaluatePassword()
    // TODO: use a ProtectedString for password

    private static final TraceComponent tc = Tr.register(InMemoryIdentityStoreDefinitionWrapper.class);

    /** The definitions for this IdentityStore. */
    private final InMemoryIdentityStoreDefinition inMemoryIdentityStoreDefinition;

    /**
     * NOTE: For priority and useFor, we do not need to store priorityExpression, nor useForExpression as they
     * effect the end values of priority and useFor respectively, but are not needed retrospectively.
     */

    /** The priority for this IdentityStore. Will be null when set by a deferred EL expression. */
    private final Integer priority;
    /** The ValidationTypes this IdentityStore can be used for. Will be null when set by a deferred EL expression. */
    private final Set<ValidationType> useFor;

    /** the raw credentials into a key/value map = <callerName = [password, groups]> */
    private final HashMap<String, CredentialValue> credentials;

    private final ELHelperWrapper elHelper;

    /**
     * Create a new instance of an {@link InMemoryIdentityStoreDefinitionWrapper} that will provide
     * convenience methods to access configuration from the {@link InMemoryIdentityStoreDefinition}
     * instance.
     *
     * @param inMemoryIdentityStoreDefinition The {@link InMemoryIdentityStoreDefinition} to wrap.
     */
    InMemoryIdentityStoreDefinitionWrapper(InMemoryIdentityStoreDefinition inMemoryIdentityStoreDefinition) {

        if (inMemoryIdentityStoreDefinition == null) {
            throw new IllegalArgumentException("The InMemoryIdentityStoreDefinition cannot be null.");
        }
        this.inMemoryIdentityStoreDefinition = inMemoryIdentityStoreDefinition;
        elHelper = new ELHelperWrapper();

        /*
         * Evaluate the configuration. The values will be non-null if the setting is NOT
         * a deferred EL expression. If it is a deferred EL expression, we will dynamically
         * evaluate it at call time.
         */

        priority = evaluatePriority(false);
        useFor = evaluateUseFor(false);

        if ((inMemoryIdentityStoreDefinition.value() == null) || (inMemoryIdentityStoreDefinition.value().length == 0)) {
            credentials = new HashMap<String, CredentialValue>(0);
        } else {
            int credentialsLength = inMemoryIdentityStoreDefinition.value().length;
            Credentials[] creds = Arrays.copyOf(inMemoryIdentityStoreDefinition.value(), credentialsLength);

            // convert raw credentials into an easily search-able HashMap with standard Java types
            credentials = new HashMap<String, CredentialValue>(credentialsLength);
            for (int i = 0; i < credentialsLength; i++) {
                CredentialValue credential = new CredentialValue(evaluatePassword(creds[i].password(), false), creds[i].groups());
                credentials.put(creds[i].callerName(), credential);
            }
        }
    }

    /**
     * Evaluate and return the password.
     *
     * @param password
     * @param immediateOnly
     * @return will return a ProtectedString representing the raw credential password
     *         or an empty ProtectedString if it wasn't in the annotation.
     */
//    @FFDCIgnore(IllegalArgumentException.class)
    private ProtectedString evaluatePassword(String password, boolean immediateOnly) {
        ProtectedString ps = null;
        if ((password != null) && (password.length() > 0)) {
            ps = new ProtectedString(password.toCharArray());
        } else {
            ps = new ProtectedString(new char[0]);
        }

        return ps;
    }

    /**
     * Evaluate and return the bindDnPassword.
     *
     * @param immediateOnly If true, only return a non-null value if the setting is either an
     *                          immediate EL expression or not set by an EL expression. If false, return the
     *                          value regardless of where it is evaluated.
     * @return The bindDnPassword or null if immediateOnly==true AND the value is not evaluated
     *         from a deferred EL expression.
     */
    @FFDCIgnore(IllegalArgumentException.class)
    private ProtectedString evaluatePassword1(String password, boolean immediateOnly) {
        String result;
        try {
            result = elHelper.processString("bindDnPassword", password, immediateOnly, true);

        } catch (IllegalArgumentException e) {
            /*
             * If deferred expression and called during initialization, return null so the expression can be re-evaluated
             * again later.
             */
            if (immediateOnly && ELHelper.isDeferredExpression(password)) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "evaluateBindDnPassword", "Returning null since bindDnPassword is a deferred expression and this is called on initialization.");
                }
                return null;
            }

            if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                Tr.warning(tc, "JAVAEESEC_WARNING_IDSTORE_CONFIG", new Object[] { "bindDnPassword", "" });
            }
            result = ""; /* Default value from spec. */
        }
        return (result == null) ? null : new ProtectedString(result.toCharArray());
    }

    /**
     * Evaluate and return the priority.
     *
     * @param immediateOnly If true, only return a non-null value if the setting is either an
     *                          immediate EL expression or not set by an EL expression. If false, return the
     *                          value regardless of where it is evaluated.
     * @return The priority or null if immediateOnly==true AND the value is not evaluated
     *         from a deferred EL expression.
     */
    @FFDCIgnore(IllegalArgumentException.class)
    private Integer evaluatePriority(boolean immediateOnly) {
        String priorityExpression = inMemoryIdentityStoreDefinition.priorityExpression();
        int priority = inMemoryIdentityStoreDefinition.priority();
        Tr.info(tc, "evaluatePriority", "priorityExpression is ["
                                        + priorityExpression
                                        + "] , priority is ["
                                        + priority
                                        + "], immediatelyOnly is ["
                                        + immediateOnly
                                        + "].");

        System.out.println("DAVE40: priorityExpression is ["
                           + priorityExpression
                           + "] , priority is ["
                           + priority
                           + "], immediatelyOnly is ["
                           + immediateOnly
                           + "].");

        try {
            return elHelper.processInt("priorityExpression", priorityExpression, priority, immediateOnly);
        } catch (IllegalArgumentException e) {
            /*
             * If deferred expression and called during initialization, return null so the expression can be re-evaluated
             * again later.
             */
            if (immediateOnly && ELHelper.isDeferredExpression(priorityExpression)) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "evaluatePriority", "Returning null since priorityExpression is a deferred expression and this is called on initialization.");
                }
                return null;
            }

            if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                Tr.warning(tc, "JAVAEESEC_WARNING_IDSTORE_CONFIG", new Object[] { "priority/priorityExpression", JakartaSec40Constants.SPEC_DEFAULT_PRIORITY });
            }
            return JakartaSec40Constants.SPEC_DEFAULT_PRIORITY;
        }
    }

    /**
     * Evaluate and return the useFor.
     *
     * @param immediateOnly If true, only return a non-null value if the setting is either an
     *                          immediate EL expression or not set by an EL expression. If false, return the
     *                          value regardless of where it is evaluated.
     * @return The useFor or null if immediateOnly==true AND the value is not evaluated
     *         from a deferred EL expression.
     */
    @FFDCIgnore(IllegalArgumentException.class)
    private Set<ValidationType> evaluateUseFor(boolean immediateOnly) {

        String useForExpression = inMemoryIdentityStoreDefinition.useForExpression();
        ValidationType[] useFor = inMemoryIdentityStoreDefinition.useFor();
        Tr.info(tc, "evaluateUseFor", "useForExpression is ["
                                      + useForExpression
                                      + "], useFor is ["
                                      + Arrays.toString(useFor)
                                      + "], immediatelyOnly is ["
                                      + immediateOnly
                                      + "].");

        System.out.println("DAVE40: useForExpression is ["
                           + useForExpression
                           + "], useFor is ["
                           + Arrays.toString(useFor)
                           + "], immediatelyOnly is ["
                           + immediateOnly
                           + "].");
        try {
            return elHelper.processUseFor(useForExpression, useFor, immediateOnly);
        } catch (IllegalArgumentException e) {
            /*
             * If deferred expression and called during initialization, return null so the expression can be re-evaluated
             * again later.
             */
            if (immediateOnly && ELHelper.isDeferredExpression(useForExpression)) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "evaluateUseFor", "Returning null since useForExpression is a deferred expression and this is called on initialization.");
                }
                return null;
            }

            Set<ValidationType> values = new HashSet<ValidationType>();
            values.addAll(JakartaSec40Constants.SPEC_DEFAULT_VALIDATION_TYPES);

            if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                Tr.warning(tc, "JAVAEESEC_WARNING_IDSTORE_CONFIG", new Object[] { "useFor/useForExpression", values });
            }
            return values;
        }
    }

    /**
     * Get the priority for the {@link IdentityStore}.
     *
     * @return The priority.
     *
     * @see InMemoryIdentityStoreDefinition#priority()
     * @see InMemoryIdentityStoreDefinition#priorityExpression()
     */
    int getPriority() {
        return (this.priority != null) ? this.priority : evaluatePriority(false);
    }

    /**
     * Get the useFor for the {@link IdentityStore}.
     *
     * @return The useFor.
     *
     * @see InMemoryIdentityStoreDefinition#useFor()
     * @see InMemoryIdentityStoreDefinition#useForExpression()
     */
    Set<ValidationType> getUseFor() {
        return (this.useFor != null) ? this.useFor : evaluateUseFor(false);
    }

    /**
     * Get the Credentials for the {@link IdentityStore} as a {@HashMap}.
     *
     * @return The annotations Credentials as a {@HashMap}, with the
     *         each Map element of the following:
     *
     *         key = String (callerValue) / value = CredentialValue ({String password, String[] groups})
     *
     *         or an empty {@HashMap} if no annotations
     *
     * @see InMemoryIdentityStoreDefinition#CredentialValue()
     */
    Map<String, CredentialValue> getCredentials() {
        return (credentials.size() != 0) ? credentials : new HashMap<String, CredentialValue>(0);
    }

    /**
     * Credentials[] getCreds1() {
     * return (creds.length != 0) ? Arrays.copyOf(creds, creds.length) : new Credentials[0];
     * }
     **/
    @Override
    public String toString() {
        StringBuffer credentialsString = new StringBuffer();
        credentials.entrySet().stream().forEach(s -> credentialsString.append(s.toString() + ","));
        credentialsString.deleteCharAt(credentialsString.length() - 1); // remove last comma
        return "InMemoryIdentityStoreDefinitionWrapper [priority=" + priority + ", useFor=" + useFor + ", creds=" + credentialsString + "]";
    }

    /***********************************************************************
     * Helper classes
     ***********************************************************************/

    private class ELHelperWrapper extends ELHelper {
        @Override
        public Set<ValidationType> processUseFor(String useForExpression, ValidationType[] useFor, boolean immediateOnly) {
            return super.processUseFor(useForExpression, useFor, immediateOnly);
        }

        @Override
        public Stream<String> processStringStream(String name, String expression, boolean immediateOnly, boolean mask) {
            return super.processStringStream(name, expression, immediateOnly, mask);
        }
    }

    /**
     * This structure models the Credentials interface, but just the password and
     * groups values, with the presumption that it is going into a
     * search-able {@HashMap) (key = callerName).
     *
     */

    public class CredentialValue {
        private final ProtectedString password;
        private final String[] groups;

        public CredentialValue(final ProtectedString password, final String[] groups) {
            this.password = password;
            this.groups = Arrays.copyOf(groups, groups.length);
        }

        public ProtectedString getPassword() {
            return password;
        }

        public String[] getGroups() {
            if ((groups == null) || (groups.length == 0)) {
                return new String[0];
            }
            return Arrays.copyOf(groups, groups.length);
        }

        @Override
        public String toString() {
            // will output the ProtectedString value of "****" for passwords
            return "CredentialValue [password=" + password + ", groups=" + Arrays.toString(groups) + "]";
        }
    }
}
