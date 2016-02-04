package org.wildfly.elytron.web.jetty.server;

import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.Configuration;
import org.eclipse.jetty.webapp.WebAppContext;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class BasicAuthenticationTest extends TestBase {

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        WebAppContext webapp = new WebAppContext();

        webapp.setContextPath("/test-app");
        webapp.setWar(createDeployment().getPath());
        webapp.getSecurityHandler().setAuthenticatorFactory(new ElytronAuthenticatorFactory());

        Server server = createServer();

        server.setHandler(webapp);
        server.addBean(createLoginService());

        server.start();
        server.dumpStdErr();
        server.join();
    }

    private Server createServer() {
        Server server = new Server(7776);

        Configuration.ClassList classlist = Configuration.ClassList
                .setServerDefault( server );
        classlist.addBefore(
                "org.eclipse.jetty.webapp.JettyWebXmlConfiguration",
                "org.eclipse.jetty.annotations.AnnotationConfiguration" );
        return server;
    }

    private HashLoginService createLoginService() throws IOException {
        HashLoginService loginService = new HashLoginService();

        loginService.setName("Test Realm");

        File identityStore = new File("/tmp/users.properties");

        if (identityStore.exists()) {
            identityStore.delete();
        }

        identityStore.createNewFile();

        try (
            FileOutputStream fos = new FileOutputStream(identityStore)
        ) {
            fos.write("elytron: elytron,user".getBytes());
        }

        loginService.setConfig(identityStore.getCanonicalPath());
        return loginService;
    }

    private File createDeployment() {
        WebArchive deployment = ShrinkWrap.create(WebArchive.class, "test-app.war");

        deployment.addAsWebInfResource(new StringAsset("<web-app version=\"3.1\" xmlns=\"http://xmlns.jcp.org/xml/ns/javaee\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                "   xsi:schemaLocation=\"http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd\">\n" +
                "   <security-constraint>" +
                "      <web-resource-collection>" +
                "         <web-resource-name>All</web-resource-name>" +
                "         <url-pattern>/*</url-pattern>" +
                "      </web-resource-collection>" +
                "      <auth-constraint>" +
                "         <role-name>user</role-name>" +
                "      </auth-constraint>" +
                "   </security-constraint>" +
                "" +
                "   <!-- Configure login to be HTTP Basic -->" +
                "   <login-config>" +
                "      <auth-method>BASIC</auth-method>" +
                "      <realm-name>Test Realm</realm-name>" +
                "   </login-config>" +
                "</web-app>"), "web.xml");

        File deploymentPath = new File("/tmp/test-app");

        deployment.add(new StringAsset("Welcome to Test App !"), "index.jsp");
        deployment.as(ZipExporter.class).exportTo(deploymentPath, true);
        return deploymentPath;
    }
}
