/*******************************************************************************
 * Copyright (c) 2017, 2021 IBM Corporation and others.
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
import java.util.HashSet;
import java.util.Set;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;

import com.ibm.websphere.ras.ProtectedString;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Default;
import jakarta.security.enterprise.credential.CallerOnlyCredential;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition.Credentials;

//import jakarta.security.enterprise.identitystore.IdentityStore.IdentityStorePermission;

/**
 * Liberty's InMemory {@link IdentityStore} implementation.
 */
@Default
@ApplicationScoped
@Component(service = {},
           immediate = true,
           configurationPolicy = ConfigurationPolicy.IGNORE,
           property = "service.vendor=IBM")
public class InMemoryIdentityStore implements IdentityStore {

    // TODO: Use the UserRegistry code to validate the password

    private static final TraceComponent tc = Tr.register(InMemoryIdentityStore.class);

    /** The definitions for this IdentityStore. */
    private final InMemoryIdentityStoreDefinitionWrapper inMemoryIdentityStoreDefinitionWrapper;

    private InitialContext initialContext = null;

    private String getIdStoreDefinitionAsString(InMemoryIdentityStoreDefinition inMemoryIdentityStoreDefinition) {

        Tr.info(tc, "InMemoryIdentityStore", "getIdStoreDefinitionAsString");
        System.out.println("getIdStoreDefinitionAsString");

        int priority = inMemoryIdentityStoreDefinition.priority();
        String priorityExpression = inMemoryIdentityStoreDefinition.priorityExpression();
        ValidationType[] useFor = inMemoryIdentityStoreDefinition.useFor();
        String useForExpression = inMemoryIdentityStoreDefinition.useForExpression();
        Credentials[] creds = inMemoryIdentityStoreDefinition.value();

        return ("priority = [" + priority + "], priorityExpression = [" + priorityExpression + "], useFor = [" + Arrays.toString(useFor)
                + "], useForExpression = [" + useForExpression + "], creds = [" + Arrays.toString(creds) + "].");
    }

    /**
     * Construct a new {@link InMemoryIdentityStore} instance using the specified definitions.
     *
     * @param idStoreDefinition The definitions to use to configure the {@link IdentityStore}.
     */

    public InMemoryIdentityStore(InMemoryIdentityStoreDefinition idStoreDefinition) {

        Tr.info(tc, "InMemoryIdentityStore", "DAVE40: InMemoryIdentityStore constructor called with idStoreDefinition1 ...");
        System.out.println("DAVE40: InMemoryIdentityStore constructor called wth idStoreDefinition1 ...");

        Tr.info(tc, "InMemoryIdentityStore", "----------------------------");
        Tr.info(tc, "InMemoryIdentityStore", "DAVE40: " + getIdStoreDefinitionAsString(idStoreDefinition));
        Tr.info(tc, "InMemoryIdentityStore", "----------------------------");
        System.out.println("----------------------------");
        System.out.println("DAVE40: " + getIdStoreDefinitionAsString(idStoreDefinition));
        System.out.println("----------------------------");

        this.inMemoryIdentityStoreDefinitionWrapper = new InMemoryIdentityStoreDefinitionWrapper(idStoreDefinition);

        Tr.info(tc, "InMemoryIdentityStore", "----------------------------");
        Tr.info(tc, "InMemoryIdentityStore", "DAVE40 (DefinitionWrapper): " + this.inMemoryIdentityStoreDefinitionWrapper.toString());
        Tr.info(tc, "InMemoryIdentityStore", "----------------------------");
        System.out.println("----------------------------");
        System.out.println("DAVE40 (DefinitionWrapper): " + this.inMemoryIdentityStoreDefinitionWrapper.toString());
        System.out.println("----------------------------");
        try {
            initialContext = new InitialContext();
        } catch (NamingException e) {
            if (tc.isEventEnabled()) {
                Tr.event(tc, "Setting up InitializeContext failed, will try later.", e);
            }
        }
    }

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        Set<String> groups = new HashSet<String>();
        if (!validationTypes().contains(ValidationType.PROVIDE_GROUPS)) {
            return groups;
        }
//        SecurityManager securityManager = System.getSecurityManager();
//        if (securityManager != null) {
//            securityManager.checkPermission(new IdentityStorePermission(JavaEESecConstants.GET_GROUPS_PERMISSION));
//        }

        String caller = validationResult.getCallerPrincipal().getName();
        if (caller == null) {
            if (tc.isEventEnabled()) {
                Tr.event(tc, "A null caller was passed into getCallerGroups. No groups returned. " + validationResult);
            }
            return groups;
        }

        // get and return the groups
        Credentials[] creds = inMemoryIdentityStoreDefinitionWrapper.getCredentials();
        for (Credentials cred : creds) {
            if (cred.callerName().equals(caller)) {
                return Set.of(cred.groups());
            }
        }

        return groups;
    }

    @Override
    public int priority() {
        return inMemoryIdentityStoreDefinitionWrapper.getPriority();
    }

    @Override
    @Sensitive
    public CredentialValidationResult validate(Credential credential) {
        if (!validationTypes().contains(ValidationType.VALIDATE)) {
            return CredentialValidationResult.NOT_VALIDATED_RESULT;
        }
        boolean callerOnly = false;
        String caller;
        ProtectedString password = null;
        if (credential instanceof UsernamePasswordCredential) {
            caller = ((UsernamePasswordCredential) credential).getCaller();
            password = new ProtectedString(((UsernamePasswordCredential) credential).getPassword().getValue());
        } else if (credential instanceof CallerOnlyCredential) {
            callerOnly = true;
            caller = ((CallerOnlyCredential) credential).getCaller();
        } else {
            Tr.error(tc, "JAVAEESEC_ERROR_WRONG_CRED");
            return CredentialValidationResult.NOT_VALIDATED_RESULT;
        }

        if (caller == null) { // should be prevented when UsernamePasswordCredential is created.
            if (tc.isEventEnabled()) {
                Tr.event(tc, "A null caller was passed in");
            }
            return CredentialValidationResult.INVALID_RESULT;
        }

        if (!callerOnly && password == null) {
            if (tc.isEventEnabled()) {
                Tr.event(tc, "A null password was passed in for caller " + caller);
            }
        }

        // validate the credentials against the stored data

        char[] pchars = password.getChars();
        Tr.info(tc, "validate", "DAVE40: caller is [" + caller + "], and password is [" + password + "].");

        StringBuffer pwd = new StringBuffer(pchars.length);
        for (char p : pchars) {
            pwd.append(p);
        }
        System.out.println("DAVE40: caller is [" + caller + "], and password is [" + pwd.toString() + "].");

        // if password is valid, then return success with groups
        if (isValid(caller, password)) {
            Set<String> groups = getCallerGroups(new CredentialValidationResult(null, caller, null, caller, null));
            Tr.info(tc, "validate", "DAVE40: groups are [" + groups.toString() + "].");
            System.out.println("DAVE40: groups are [" + groups.toString() + "].");
            return new CredentialValidationResult(null, caller, null, caller, groups);
        } else {
            return CredentialValidationResult.INVALID_RESULT;
        }

    }

    private boolean isValid(String caller, ProtectedString password) {
        Credentials[] creds = inMemoryIdentityStoreDefinitionWrapper.getCredentials();

        for (Credentials cred : creds) {
            if (cred.callerName().equals(caller)) {
                char[] pchars = password.getChars();
                StringBuffer pwd = new StringBuffer(pchars.length);
                for (char p : pchars) {
                    pwd.append(p);
                }
                if (pwd.toString().equals(cred.password())) {
                    return true;
                }
            }
        }

        // TODO
        return false;
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return inMemoryIdentityStoreDefinitionWrapper.getUseFor();
    }

}
