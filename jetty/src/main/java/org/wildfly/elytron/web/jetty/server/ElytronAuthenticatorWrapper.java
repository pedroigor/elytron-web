package org.wildfly.elytron.web.jetty.server;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.List;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAuthenticatorWrapper implements Authenticator {

    private final AuthConfiguration configuration;
    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;

    public ElytronAuthenticatorWrapper(AuthConfiguration configuration, Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
        this.configuration = configuration;
        this.mechanismSupplier = mechanismSupplier;
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        // no-op
    }

    @Override
    public String getAuthMethod() {
        return this.configuration.getAuthMethod();
    }

    @Override
    public void prepareRequest(ServletRequest request) {

    }

    @Override
    public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) throws ServerAuthException {
        HttpAuthenticator authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(mechanismSupplier)
                .setHttpExchangeSpi(new ElytronHttpExchange(request, response))
                .setRequired(mandatory)
                .setIgnoreOptionalFailures(false) // TODO - Cover this one later.
                .build();

        try {
            if (authenticator.authenticate()) {
                return Authentication.SEND_SUCCESS;
            }
        } catch (HttpAuthenticationException e) {
        }

        return Authentication.SEND_FAILURE;
    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, Authentication.User validatedUser) throws ServerAuthException {
        return false;
    }
}
