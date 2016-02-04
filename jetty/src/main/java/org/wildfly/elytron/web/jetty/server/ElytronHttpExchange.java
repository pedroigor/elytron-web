package org.wildfly.elytron.web.jetty.server;

import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.MultiMap;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.Cookie;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpServerSession;

import javax.security.auth.Subject;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronHttpExchange implements HttpExchangeSpi {

    private final Request request;
    private final Response response;

    public ElytronHttpExchange(Request request, Response response) {
        this.request = request;
        this.response = response;
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        Enumeration<String> headerEnum = this.request.getHeaders(headerName);

        if (headerEnum == null) {
            return Collections.emptyList();
        }

        List<String> values = new ArrayList<>();

        while (headerEnum.hasMoreElements()) {
            values.add(headerEnum.nextElement());
        }

        return Collections.unmodifiableList(values);
    }

    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        this.response.addHeader(headerName, headerValue);
    }

    @Override
    public void setResponseCode(int responseCode) {
        this.response.setStatus(responseCode);
    }

    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        Subject subject = new Subject();
        Principal principal = securityIdentity.getPrincipal();
        Set<String> roles = securityIdentity.getRoles();

        this.request.setAuthentication(new UserAuthentication(this.request.getAuthType(), new DefaultUserIdentity(subject, principal, roles.toArray(new String[roles.size()]))) {
            @Override
            public void logout() {

            }
        });
    }

    @Override
    public void authenticationFailed(String message, String mechanismName) {

    }

    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {

    }

    @Override
    public String getRequestMethod() {
        return this.request.getMethod();
    }

    @Override
    public String getRequestURI() {
        return this.request.getRequestURI();
    }

    @Override
    public Map<String, String[]> getQueryParameters() {
        MultiMap<String> queryParameters = this.request.getQueryParameters();

        if (queryParameters != null) {
            Map<String, String[]> transformed = new HashMap();

            queryParameters.forEach((name, values) -> transformed.put(name, values.toArray(new String[values.size()])));

            return transformed;
        }

        return Collections.emptyMap();
    }

    @Override
    public Cookie[] getCookies() {
        List<Cookie> cookies = Stream.of(this.request.getCookies()).map(new Function<javax.servlet.http.Cookie, Cookie>() {
            @Override
            public Cookie apply(javax.servlet.http.Cookie cookie) {
                return new Cookie() {
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
                        return cookie.getSecure();
                    }

                    @Override
                    public int getVersion() {
                        return cookie.getVersion();
                    }

                    @Override
                    public boolean isHttpOnly() {
                        return cookie.isHttpOnly();
                    }
                };
            }
        }).collect(Collectors.toList());

        return cookies.toArray(new Cookie[cookies.size()]);
    }

    @Override
    public InputStream getInputStream() {
        try {
            return this.request.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return this.request.getRemoteInetSocketAddress();
    }

    @Override
    public void setResponseCookie(Cookie cookie) {
        this.response.addCookie(new HttpCookie(cookie.getName(), cookie.getValue(), cookie.getDomain(), cookie.getPath(), cookie.getMaxAge(), cookie.isHttpOnly(), cookie.isSecure(), null, cookie.getVersion()));
    }

    @Override
    public OutputStream getOutputStream() {
        try {
            return this.response.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public HttpServerSession getSession(boolean create) {
        HttpSession session = this.request.getSession(create);

        return createSession(session);
    }

    private HttpServerSession createSession(final HttpSession session) {
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
                Object attribute = session.getAttribute(name);

                session.removeAttribute(name);

                return attribute;
            }

            @Override
            public void invalidate() {
                session.invalidate();
            }
        };
    }

    @Override
    public HttpServerSession getSession(String id) {
        return createSession(this.request.getSessionManager().getHttpSession(id));
    }

    @Override
    public Set<String> getSessions() {
        return Collections.emptySet();
    }
}
