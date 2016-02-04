package org.wildfly.elytron.web.jetty.server;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.Server;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
import org.wildfly.security.http.util.AggregateServerMechanismFactory;
import org.wildfly.security.http.util.ServiceLoaderServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;

import javax.servlet.ServletContext;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAuthenticatorFactory implements Authenticator.Factory {

    private HttpAuthenticationFactory httpAuthenticationFactory;
    private String securityRealmType;
    private String roleDecoderType;

    public ElytronAuthenticatorFactory() throws Exception {

    }

    @Override
    public Authenticator getAuthenticator(Server server, ServletContext context, Authenticator.AuthConfiguration configuration, IdentityService identityService, LoginService loginService) {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
            SecurityDomain.Builder builder = SecurityDomain.builder()
                    .setDefaultRealmName("TestRealm");

            builder.addRealm("TestRealm", (SecurityRealm) Thread.currentThread().getContextClassLoader().loadClass(this.securityRealmType).newInstance()).setRoleDecoder((RoleDecoder) Thread.currentThread().getContextClassLoader().loadClass(this.roleDecoderType).newInstance());

            httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                    .setSecurityDomain(builder.build())
                    .addMechanism("BASIC",
                            MechanismConfiguration.builder()
                                    .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                    .build()
                    )
                    .addMechanism("KEYCLOAK",
                            MechanismConfiguration.builder()
                                    .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                    .build()
                    )
                    .setFactory(new AggregateServerMechanismFactory(new ServerMechanismFactoryImpl(), new ServiceLoaderServerMechanismFactory(Thread.currentThread().getContextClassLoader())))
                    .build();

            return new ElytronAuthenticatorWrapper(configuration, new Supplier<List<HttpServerAuthenticationMechanism>>() {
                @Override
                public List<HttpServerAuthenticationMechanism> get() {
                    return getAuthenticationMechanisms();
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private List<HttpServerAuthenticationMechanism> getAuthenticationMechanisms() {
        return httpAuthenticationFactory.getMechanismNames().stream()
                .map(new Function<String, HttpServerAuthenticationMechanism>() {
                    @Override
                    public HttpServerAuthenticationMechanism apply(String s) {
                        return createMechanism(s);
                    }
                })
                .filter(m -> m != null)
                .collect(Collectors.toList());
    }

    private HttpServerAuthenticationMechanism createMechanism(final String mechanismName) {
        try {
            return httpAuthenticationFactory.createMechanism(mechanismName);
        } catch (HttpAuthenticationException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void setSecurityRealmType(String securityRealmType) {
        this.securityRealmType = securityRealmType;
    }

    public void setRoleDecoderType(String roleDecoderType) {
        this.roleDecoderType = roleDecoderType;
    }
}
