/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.elytron.web.undertow.server;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.Scope;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.handlers.AbstractSecurityContextAssociationHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronContextAssociationHandler extends AbstractSecurityContextAssociationHandler {

    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
    private final Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers;

    /**
     * @param next
     */
    private ElytronContextAssociationHandler(Builder builder) {
        super(checkNotNullParam("next", builder.next));

        this.mechanismSupplier = checkNotNullParam("mechanismSupplier", builder.mechanismSupplier);
        this.scopeResolvers = builder.scopeResolvers;
    }

    /**
     * Create a new Elytron backed {@link SecurityContext}.
     */
    @Override
    public SecurityContext createSecurityContext(HttpServerExchange exchange) {
        return SecurityContextImpl.builder()
                .setExchange(exchange)
                .setMechanismSupplier(mechanismSupplier)
                .setScopeResolvers(scopeResolvers)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        HttpHandler next;
        Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
        final Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers = new HashMap<>();

        private Builder() {
        }

        public Builder setNext(HttpHandler next) {
            this.next = next;

            return this;
        }

        public Builder setMechanismSupplier(Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
            this.mechanismSupplier = mechanismSupplier;

            return this;
        }

        public Builder addScopeResolver(Scope scope, Function<HttpServerExchange, HttpScope> scopeResolver) {
            scopeResolvers.put(scope, scopeResolver);

            return this;
        }

        public HttpHandler build() {
            return new ElytronContextAssociationHandler(this);
        }
    }
}
