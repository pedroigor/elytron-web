package org.wildfly.elytron.web.jetty.server;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronHttpExchange implements HttpExchangeSpi {

    private final ServletResponse response;
    private final ServletRequest request;

    public ElytronHttpExchange(ServletRequest request, ServletResponse response) {
        this.request = request;
        this.response = response;
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        return null;
    }

    @Override
    public void addResponseHeader(String headerName, String headerValue) {

    }

    @Override
    public void setResponseCode(int responseCode) {

    }

    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {

    }

    @Override
    public void authenticationFailed(String message, String mechanismName) {

    }

    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {

    }
}
