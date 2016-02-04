package org.wildfly.elytron.web.jetty.server;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.Server;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import javax.servlet.ServletContext;
import java.util.List;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAuthenticatorFactory implements Authenticator.Factory {

    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;

    public ElytronAuthenticatorFactory(Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
        this.mechanismSupplier = mechanismSupplier;
    }

    @Override
    public Authenticator getAuthenticator(Server server, ServletContext context, Authenticator.AuthConfiguration configuration, IdentityService identityService, LoginService loginService) {
        return new ElytronAuthenticatorWrapper(configuration, this.mechanismSupplier);
    }
}
