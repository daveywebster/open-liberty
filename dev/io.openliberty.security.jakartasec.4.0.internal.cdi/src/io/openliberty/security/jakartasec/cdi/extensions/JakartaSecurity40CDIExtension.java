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
package io.openliberty.security.jakartasec.cdi.extensions;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.security.javaeesec.JavaEESecConstants;

import io.openliberty.security.jakartasec.JakartaSec40Constants;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.AfterBeanDiscovery;
import jakarta.enterprise.inject.spi.AnnotatedType;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.enterprise.inject.spi.ProcessAnnotatedType;
import jakarta.enterprise.inject.spi.WithAnnotations;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStore.ValidationType;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition;

/**
 * CDI Extension to process the {@link InMemoryIdentityStoreDefinition} annotation
 * and register beans required for Jakarta Security 4.0.
 */

@Component(service = {},
           immediate = true,
           configurationPolicy = ConfigurationPolicy.IGNORE,
           property = "service.vendor=IBM")
public class JakartaSecurity40CDIExtension implements Extension {

    private static final TraceComponent tc = Tr.register(JakartaSecurity40CDIExtension.class);

    private final Set<Bean<IdentityStore>> beansToAdd = new HashSet<Bean<IdentityStore>>();

    public JakartaSecurity40CDIExtension() {
        // empty
    }

    public <T> void processAnnotatedInMemory(@WithAnnotations({ InMemoryIdentityStoreDefinition.class }) @Observes ProcessAnnotatedType<T> event, BeanManager beanManager) {
        AnnotatedType<T> annotatedType = event.getAnnotatedType();
        Annotation inMemoryAnnotation = annotatedType.getAnnotation(InMemoryIdentityStoreDefinition.class);
        addInMemoryIdentityStoreBean(inMemoryAnnotation, beanManager);
    }

    private <T> void addInMemoryIdentityStoreBean(Annotation inMemoryAnnotation, BeanManager beanManager) {

        Class<? extends Annotation> annotationType = inMemoryAnnotation.annotationType();

        for (Bean<IdentityStore> b : beansToAdd) {
            if (InMemoryIdentityStoreBean.class.equals(b.getClass())) {
                if (tc.isDebugEnabled())
                    Tr.debug(tc, "InMemoryIdentityStoreBean already registered.");
                return;
            }
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "adding InMemoryIdentityStoreBean.");
        }

        try {
            Map<String, Object> identityStoreProperties = new HashMap<String, Object>();
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "JavaEESec.createInMemoryIdentityStoreBeanToAdd");
            }
            Method[] methods = annotationType.getMethods();
            for (Method m : methods) {
                Tr.debug(tc, m.getName());
                if (!m.getName().equals("equals")) {
                    identityStoreProperties.put(m.getName(), m.invoke(inMemoryAnnotation));
                }
            }

            InMemoryIdentityStoreDefinition inMemoryIdentityStoreDefinition = getInstanceOfInMemoryAnnotation(identityStoreProperties);

            beansToAdd.add(new InMemoryIdentityStoreBean(beanManager, inMemoryIdentityStoreDefinition));
        } catch (InvocationTargetException | IllegalAccessException e) {
            if (tc.isEventEnabled()) {
                Tr.event(tc, "unexpected", e);
            }
        }
    }

    private InMemoryIdentityStoreDefinition getInstanceOfInMemoryAnnotation(final Map<String, Object> overrides) {
        InMemoryIdentityStoreDefinition annotation = new InMemoryIdentityStoreDefinition() {

            @Override
            public Class<? extends Annotation> annotationType() {
                return null;
            }

            @Override
            public int priority() {
                return (overrides != null &&
                        overrides.containsKey(JavaEESecConstants.PRIORITY)) ? (Integer) overrides.get(JavaEESecConstants.PRIORITY) : 70;
            }

            @Override
            public String priorityExpression() {
                return (overrides != null &&
                        overrides.containsKey(JavaEESecConstants.PRIORITY_EXPRESSION)) ? (String) overrides.get(JavaEESecConstants.PRIORITY_EXPRESSION) : "";
            }

            @Override
            public ValidationType[] useFor() {
                return (overrides != null &&
                        overrides.containsKey(JavaEESecConstants.USE_FOR)) ? (ValidationType[]) overrides.get(JavaEESecConstants.USE_FOR) : new ValidationType[] { ValidationType.PROVIDE_GROUPS,
                                                                                                                                                                   ValidationType.VALIDATE };
            }

            @Override
            public String useForExpression() {
                return (overrides != null && overrides.containsKey(JavaEESecConstants.USE_FOR_EXPRESSION)) ? (String) overrides.get(JavaEESecConstants.USE_FOR_EXPRESSION) : "";
            }

            @Override
            public Credentials[] value() {
                return (overrides != null
                        && overrides.containsKey(JakartaSec40Constants.VALUE)) ? (Credentials[]) overrides.get(JakartaSec40Constants.VALUE) : new Credentials[] {};
            }
        };
        return annotation;
    }

    public <T> void afterBeanDiscovery(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "afterBeanDiscovery : instance : " + Integer.toHexString(this.hashCode()) + " BeanManager : " + Integer.toHexString(beanManager.hashCode()));
        }

        // Verification of mechanisms and registration of ModulePropertiesProviderBean performed in JavaEESecCDIExtension's afterBeanDiscovery()
        for (Bean<IdentityStore> bean : beansToAdd) {
            afterBeanDiscovery.addBean(bean);
        }
    }
}
