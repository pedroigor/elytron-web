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

import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionManager;
import io.undertow.util.HttpString;
import io.undertow.util.Sessions;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.Cookie;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpServerSession;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * Implementation of {@link HttpExchangeSpi} to wrap access to the Undertow specific {@link HttpServerExchange}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronHttpExchange implements HttpExchangeSpi {

    private final HttpServerExchange httpServerExchange;

    ElytronHttpExchange(final HttpServerExchange httpServerExchange) {
        this.httpServerExchange = checkNotNullParam("httpServerExchange", httpServerExchange);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestHeaderValues(java.lang.String)
     */
    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        return httpServerExchange.getRequestHeaders().get(headerName);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#addResponseHeader(java.lang.String, java.lang.String)
     */
    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        httpServerExchange.getResponseHeaders().add(new HttpString(headerName), headerValue);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#setResponseCode(int)
     */
    @Override
    public void setResponseCode(int responseCode) {
        httpServerExchange.setResponseCode(responseCode);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationComplete(org.wildfly.security.auth.spi.AuthenticatedRealmIdentity, java.lang.String)
     */
    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        SecurityContext securityContext = httpServerExchange.getSecurityContext();
        if (securityContext != null) {
            securityContext.authenticationComplete(new ElytronAccount(securityIdentity), mechanismName, false);
        }
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationFailed(java.lang.String, java.lang.String)
     */
    @Override
    public void authenticationFailed(String message, String mechanismName) {
        SecurityContext securityContext = httpServerExchange.getSecurityContext();
        if (securityContext != null) {
            securityContext.authenticationFailed(message, mechanismName);
        }
    }

    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {
    }

    @Override
    public String getRequestMethod() {
        return httpServerExchange.getRequestMethod().toString();
    }

    @Override
    public String getRequestURI() {
        StringBuilder uriBuilder = new StringBuilder();

        if (!httpServerExchange.isHostIncludedInRequestURI()) {
            uriBuilder.append(httpServerExchange.getRequestScheme()).append("://").append(httpServerExchange.getHostAndPort());
        }

        uriBuilder.append(httpServerExchange.getRequestURI());

        String queryString = httpServerExchange.getQueryString();

        if (queryString != null && !"".equals(queryString.trim())) {
            uriBuilder.append("?").append(queryString);
        }

        return uriBuilder.toString();
    }

    @Override
    public Map<String, String[]> getQueryParameters() {
        HashMap<String, String[]> parameters = new HashMap<>();

        httpServerExchange.getQueryParameters().forEach((name, values) -> parameters.put(name, values.toArray(new String[values.size()])));

        return parameters;
    }

    @Override
    public Cookie[] getCookies() {
        Map<String, io.undertow.server.handlers.Cookie> cookies = httpServerExchange.getRequestCookies();
        return cookies.values().stream().map((Function<io.undertow.server.handlers.Cookie, Cookie>) cookie -> new Cookie() {
            @Override
            public String getName() {
                return cookie.getName();
            }

            @Override
            public String getValue() {
                return cookie.getValue();
            }

            @Override
            public String getDomain() {
                return cookie.getDomain();
            }

            @Override
            public int getMaxAge() {
                return cookie.getMaxAge();
            }

            @Override
            public String getPath() {
                return cookie.getPath();
            }

            @Override
            public boolean isSecure() {
                return cookie.isSecure();
            }

            @Override
            public int getVersion() {
                return cookie.getVersion();
            }

            @Override
            public boolean isHttpOnly() {
                return cookie.isHttpOnly();
            }
        }).collect(Collectors.toList()).toArray(new Cookie[cookies.size()]);
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return httpServerExchange.getSourceAddress();
    }

    @Override
    public void setResponseCookie(Cookie cookie) {
        CookieImpl actualCookie = new CookieImpl(cookie.getName(), cookie.getValue());

        actualCookie.setDomain(cookie.getDomain());
        actualCookie.setMaxAge(cookie.getMaxAge());
        actualCookie.setHttpOnly(cookie.isHttpOnly());
        actualCookie.setSecure(cookie.isSecure());
        actualCookie.setPath(cookie.getPath());

        httpServerExchange.setResponseCookie(actualCookie);
    }

    @Override
    public OutputStream getOutputStream() {
        return null;
    }

    @Override
    public HttpServerSession getSession(boolean create) {
        Session session;

        if (create) {
            session = Sessions.getOrCreateSession(httpServerExchange);
        } else {
            session = Sessions.getSession(httpServerExchange);
        }

        if (session == null) {
            return null;
        }

        return createSession(session);
    }

    private HttpServerSession createSession(final Session session) {
        return new HttpServerSession() {
            @Override
            public String getId() {
                return session.getId();
            }

            @Override
            public Object getAttribute(String name) {
                return session.getAttribute(name);
            }

            @Override
            public void setAttribute(String name, Object value) {
                session.setAttribute(name, value);
            }

            @Override
            public Object removeAttribute(String name) {
                return session.removeAttribute(name);
            }

            @Override
            public void invalidate() {
                session.invalidate(httpServerExchange);
            }
        };
    }

    @Override
    public HttpServerSession getSession(String id) {
        SessionManager sessionManager = httpServerExchange.getAttachment(SessionManager.ATTACHMENT_KEY);
        Session session = sessionManager.getSession(id);

        if (session == null) {
            return null;
        }

        return createSession(session);
    }

}
