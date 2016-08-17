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

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.handlers.AuthenticationConstraintHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.session.SessionAttachmentHandler;
import io.undertow.server.session.SessionCookieConfig;
import io.undertow.server.session.SessionManager;
import io.undertow.util.StatusCodes;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.server.util.InfinispanSessionManager;
import org.wildfly.elytron.web.undertow.server.util.SessionInvalidationHandler;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.PropertiesServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class FormAuthenticationWithSessionReplicationTest extends TestBase {

    private static final String NODE_A_URI = "http://localhost:7776";
    private static final String NODE_B_URI = "http://localhost:7777";
    private static final String NODE_C_URI = "http://localhost:7778";
    private List<SessionManager> sessionManager = new ArrayList<>();
    private Undertow nodeA;
    private Undertow nodeB;
    private Undertow nodeC;

    @Before
    public void onBefore() throws Exception {
        nodeA = createServer(7776);
        nodeB = createServer(7777);
        nodeC = createServer(7778);
    }

    @After
    public void onAfter() throws Exception {
        this.sessionManager.forEach(SessionManager::stop);
        nodeA.stop();
        nodeB.stop();
        nodeC.stop();
    }

    @Test
    public void testSessionReplication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();

        assertLoginPage(httpClient.execute(new HttpGet(NODE_A_URI)));

        // authenticate on NODE_A
        HttpPost httpAuthenticate = new HttpPost(NODE_A_URI + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessFulResponse(httpClient.execute(httpAuthenticate));
        assertSuccessFulResponse(httpClient.execute(new HttpGet(NODE_B_URI)));
        assertSuccessFulResponse(httpClient.execute(new HttpGet(NODE_C_URI)));

        httpClient.execute(new HttpGet(NODE_B_URI + "/logout"));

        assertLoginPage(httpClient.execute(new HttpGet(NODE_C_URI)));
        assertLoginPage(httpClient.execute(new HttpGet(NODE_A_URI)));
        assertLoginPage(httpClient.execute(new HttpGet(NODE_B_URI)));
    }

    private Undertow createServer(int port) throws Exception {
        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", createDefaultSecurityRealm()).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));
        SecurityDomain securityDomain = builder.build();

        HashMap properties = new HashMap();

        properties.put(HttpConstants.CONFIG_LOGIN_PAGE, "/login.html");
        properties.put(HttpConstants.CONFIG_ERROR_PAGE, "/error.html");

        HttpServerAuthenticationMechanismFactory factory = new PropertiesServerMechanismFactory(new FilterServerMechanismFactory(new ServerMechanismFactoryImpl(), true, "FORM"), properties);
        HttpAuthenticationFactory httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .setFactory(factory)
                .build();

        HttpHandler securityHandler = new ElytronRunAsHandler(new SessionInvalidationHandler(new ResponseHandler(securityDomain)));

        securityHandler = new BlockingHandler(securityHandler);
        securityHandler = new AuthenticationCallHandler(securityHandler);
        securityHandler = new AuthenticationConstraintHandler(securityHandler);
        securityHandler = ElytronContextAssociationHandler.builder()
                .setNext(securityHandler)
                .setMechanismSupplier(() -> getAuthenticationMechanisms(httpAuthenticationFactory))
                .build();

        SessionManager sessionManager = createSessionManager();

        sessionManager.start();

        this.sessionManager.add(sessionManager);

        securityHandler = Handlers.path(new SessionAttachmentHandler(securityHandler, sessionManager, new SessionCookieConfig()));

        PathHandler rootHandler = Handlers.path();

        rootHandler = rootHandler
                .addExactPath("/login.html", exchange -> {
                    exchange.getResponseSender().send("Login Page");
                    exchange.endExchange();
                })
                .addPrefixPath("/", securityHandler);

        Undertow server = Undertow.builder().addHttpListener(port, "localhost").setHandler(rootHandler).build();
        server.start();
        return server;
    }

    private void assertLoginPage(HttpResponse response) throws Exception {
        assertTrue(EntityUtils.toString(response.getEntity()).contains("Login Page"));
    }

    private SimpleMapBackedSecurityRealm createDefaultSecurityRealm() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();
        passwordMap.put("ladybird", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));
        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm();
        simpleRealm.setPasswordMap(passwordMap);
        return simpleRealm;
    }

    private void assertSuccessFulResponse(HttpResponse result) throws IOException {
        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());

        Header[] values = result.getHeaders("ProcessedBy");
        assertEquals(1, values.length);
        assertEquals("ResponseHandler", values[0].getValue());

        values = result.getHeaders("UndertowUser");
        assertEquals(1, values.length);
        assertEquals("ladybird", values[0].getValue());

        values = result.getHeaders("ElytronUser");
        assertEquals(1, values.length);
        assertEquals("ladybird", values[0].getValue());

        readResponse(result);
    }

    private static String readResponse(final HttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            return "";
        }
        return readResponse(entity.getContent());
    }

    private static String readResponse(InputStream stream) throws IOException {

        byte[] data = new byte[100];
        int read;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ((read = stream.read(data)) != -1) {
            out.write(data, 0, read);
        }
        return new String(out.toByteArray(), Charset.forName("UTF-8"));
    }

    private static HttpServerAuthenticationMechanism createMechanism(String mechanismName, HttpAuthenticationFactory httpAuthenticationFactory) {
        try {
            return httpAuthenticationFactory.createMechanism(mechanismName);
        } catch (HttpAuthenticationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static List<HttpServerAuthenticationMechanism> getAuthenticationMechanisms(HttpAuthenticationFactory httpAuthenticationFactory) {
        return httpAuthenticationFactory.getMechanismNames().stream()
                .map(mechanismName -> createMechanism(mechanismName, httpAuthenticationFactory))
                .filter(m -> m != null)
                .collect(Collectors.toList());
    }

    private static SessionManager createSessionManager() {
        return new InfinispanSessionManager(UUID.randomUUID().toString());
    }
}
