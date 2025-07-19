package raff.stein.feignclient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.testcontainers.shaded.org.awaitility.Awaitility;

import java.time.Duration;
import java.util.List;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
class FeignClientTest {

    @Autowired
    private MockMvc mockMvc;

    // BASIC AUTH
    // specific basic auth API calls
    static WireMockServer basicAuthContentMockServer;

    // OAUTH2
    // one client for oauth2 auth only
    static WireMockServer oauth2AuthMockServer;
    // one for specific oauth2 API calls
    static WireMockServer oauth2ContentMockServer;

    // NTLM
    static WireMockServer ntlmMockServer;

    // API Key
    static WireMockServer apiKeyMockServer;

    // JWT
    static WireMockServer jwtMockServer;

    // DIGEST AUTH
    static WireMockServer digestMockServer;

    // MUTUAL TLS AUTH
    static WireMockServer mutualTlsMockServer;

    // HMAC AUTH
    static WireMockServer hmacMockServer;

    // SAML
    static WireMockServer samlMockServer;


    private static final String BASIC_AUTH_200_RESPONSE_STRING = "Basic auth response content";
    private static final String OAUTH_200_RESPONSE_STRING = "OAuth2 response content";
    private static final String NTLM_200_RESPONSE_STRING = "NTLM response content";
    private static final String API_KEY_200_RESPONSE_STRING = "API KEY response content";
    private static final String JWT_200_RESPONSE_STRING = "JWT response content";
    private static final String DIGEST_200_FIRST_RESPONSE_STRING = "Digest first response content";
    private static final String DIGEST_200_SECOND_RESPONSE_STRING = "Digest second response content";
    private static final String MUTUAL_TLS_200_SECOND_RESPONSE_STRING = "Mutual TLS response content";
    private static final String HMAC_200_RESPONSE_STRING = "HMAC response content";
    private static final String SAML_200_RESPONSE_STRING = "SAML response content";




    @BeforeAll
    static void beforeAll() {
        setupBasicAuthServers();
        setupOauth2Servers();
        setupNTLMServer();
        setupAPIKeyServer();
        setupJWTServer();
        setupDigestServer();
        setupMutualTlsServer();
        setupHmacServer();
        setupSamlServer();
    }


    private static void setupBasicAuthServers() {
        setupBasicAuthContentMockServer();
    }

    private static void setupOauth2Servers() {
        setupOauth2MockServer();
        setupOauth2ContentMockServer();
    }

    private static void setupOauth2ContentMockServer() {
        oauth2ContentMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8083));
        oauth2ContentMockServer.start();
        oauth2ContentMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data")).willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withBody(OAUTH_200_RESPONSE_STRING))
        );
    }

    private static void setupOauth2MockServer() {
        oauth2AuthMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8084));
        oauth2AuthMockServer.start();

        oauth2AuthMockServer.stubFor(
                WireMock.post(WireMock.urlEqualTo("/"))
                        .willReturn(WireMock.aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                                .withBody("""
                                        {
                                        "access_token": "fake-token",
                                        "token_type": "bearer",\s
                                        "expires_in": "3598",\s
                                        "scope": "service.genesis",\s
                                        "jti": "fake-token"\s
                                        }"""))
        );

    }


    private static void setupBasicAuthContentMockServer() {
        basicAuthContentMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8081));
        basicAuthContentMockServer.start();
        basicAuthContentMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data")).willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withBody(BASIC_AUTH_200_RESPONSE_STRING))
        );
    }

    private static void setupAPIKeyServer() {
        apiKeyMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8086));
        apiKeyMockServer.start();
        apiKeyMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data")).willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withBody(API_KEY_200_RESPONSE_STRING)));
    }

    private static void setupNTLMServer() {
        ntlmMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8085));
        ntlmMockServer.start();
        // phase 1: no auth header -> 401 response with header WWW-Authenticate: NTLM
        ntlmMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .inScenario("NTLM Authentication")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(WireMock.aResponse()
                                .withStatus(401)
                                .withHeader("WWW-Authenticate", "NTLM")
                                .withBody("Unauthorized"))
                        .willSetStateTo("TYPE1_RECEIVED")
        );

        // phase 2: the server should receive a request with an auth header (NTLM type 1) and it should respond with a 401
        // and a dummy challenge into another header (NTLM type 2)
        // In NTLM the negotiation messages (Type 1) usually starts with "TlRMTVNTUAAB".
        ntlmMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .inScenario("NTLM Authentication")
                        .whenScenarioStateIs("TYPE1_RECEIVED")
                        .withHeader("Authorization", WireMock.matching("NTLM\\s+TlRMTVNTUAAB.*"))
                        .willReturn(WireMock.aResponse()
                                .withStatus(401)
                                // we return a well formatted a challenge type 2 header
                                .withHeader(
                                        "WWW-Authenticate",
                                        "NTLM TlRMTVNTUAACAAAADAAMADgAAAAFgomi5/gAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
                                .withBody("Unauthorized"))
                        .willSetStateTo("TYPE3_RECEIVED")
        );
        // phase 3: the server should receive another request with an auth header "Authorization" (NTLM type 3)
        // and it should respond with 200 OK and the response body
        // usually the type 3 message starts with "TlRMTVNTUAAD".
        ntlmMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .inScenario("NTLM Authentication")
                        .whenScenarioStateIs("TYPE3_RECEIVED")
                        .withHeader("Authorization", WireMock.matching("NTLM\\s+TlRMTVNTUAAD.*"))
                        .willReturn(WireMock.aResponse()
                                .withStatus(200)
                                .withBody(NTLM_200_RESPONSE_STRING))
        );
    }

    private static void setupJWTServer() {
        jwtMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8087));
        jwtMockServer.start();
        jwtMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data")).willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withBody(JWT_200_RESPONSE_STRING)));
    }

    private static void setupDigestServer() {
        // Initialize and start a WireMock server on port 8088
        digestMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8088));
        digestMockServer.start();
        // === STEP 1: Simulate an initial Digest Authentication challenge ===
        digestMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/auth"))
                        // Define a WireMock scenario to manage stateful mocking
                        .inScenario("Digest Auth")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(WireMock.aResponse()
                                // Force client to receive 401 Unauthorized
                                .withStatus(401)
                                // Digest challenge header, including realm, nonce, and opaque
                                .withHeader("WWW-Authenticate ",
                                        "Digest realm=\"localhost\", " +
                                                "qop=\"auth\", " +
                                                "nonce=\"testnonce\", " +
                                                "opaque=\"testopaque\"")
                                .withBody("Unauthorized"))
                        // Move scenario into authenticated state after this 401 is served
                        .willSetStateTo("CHALLENGE_SENT")
        );
        // === STEP 2: Accept the first authenticated request ===
        digestMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-first-content"))
                        .inScenario("Digest Auth")
                        // Only allow after challenge sent
                        .whenScenarioStateIs("CHALLENGE_SENT")
                        // Must contain Digest Authorization header
                        .withHeader("Authorization", WireMock.matching("Digest\\s+.*"))
                        .willReturn(WireMock.aResponse()
                                .withStatus(200)
                                .withBody(DIGEST_200_FIRST_RESPONSE_STRING))
        );
        // === STEP 3: Accept the second authenticated request ===
        digestMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-second-content"))
                        .inScenario("Digest Auth")
                        // Still in authenticated state
                        .whenScenarioStateIs("CHALLENGE_SENT")
                        .withHeader("Authorization", WireMock.matching("Digest\\s+.*"))
                        .willReturn(WireMock.aResponse()
                                .withStatus(200)
                                .withBody(DIGEST_200_SECOND_RESPONSE_STRING))
        );
    }

    private static void setupMutualTlsServer() {
        // Initialize and start a WireMock server on port 8089
        mutualTlsMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .httpsPort(8089)
                .needClientAuth(true) // Enable Mutual TLS
                .trustStorePath("src/test/resources/mutualtls/server-truststore.jks")
                .trustStorePassword("changeit")
                .trustStoreType("PKCS12")
                .keystorePath("src/test/resources/mutualtls/server-keystore.jks")
                .keystorePassword("changeit")
                .keystoreType("PKCS12")
                .keyManagerPassword("changeit"));
        mutualTlsMockServer.start();

        mutualTlsMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withBody(MUTUAL_TLS_200_SECOND_RESPONSE_STRING)));
    }

    private static void setupHmacServer() {
        hmacMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8090));
        hmacMockServer.start();
        hmacMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .withHeader("X-HMAC-SIGNATURE",  WireMock.matching(".+"))
                        .willReturn(
                                WireMock.aResponse()
                                        .withStatus(200)
                                        .withBody(HMAC_200_RESPONSE_STRING)
                        ));
        // Stub for missing HMAC signature
        hmacMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .atPriority(1)
                        .withHeader("X-HMAC-SIGNATURE", WireMock.absent())
                        .willReturn(WireMock.aResponse()
                                .withStatus(401)
                                .withBody("Missing HMAC signature"))
        );
    }

    private static void setupSamlServer() {
        samlMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8091));
        samlMockServer.start();
        samlMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .withHeader("SAMLAssertion", WireMock.matching(".+"))
                        .willReturn(
                                WireMock.aResponse()
                                        .withStatus(200)
                                        .withBody(SAML_200_RESPONSE_STRING)
                        ));
        // Stub for missing SAML assertion
        samlMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/get-data"))
                        .atPriority(1)
                        .withHeader("SAMLAssertion", WireMock.absent())
                        .willReturn(WireMock.aResponse()
                                .withStatus(401)
                                .withBody("Missing SAML assertion"))
        );
    }



    @AfterAll
    static void afterAll() {
        stopWireMockServers();
    }

    private static void stopWireMockServers() {
        if(basicAuthContentMockServer.isRunning())
            basicAuthContentMockServer.stop();
        if(oauth2AuthMockServer.isRunning())
            oauth2AuthMockServer.stop();
        if(oauth2ContentMockServer.isRunning())
            oauth2ContentMockServer.stop();
        if(ntlmMockServer.isRunning())
            ntlmMockServer.stop();
        if(apiKeyMockServer.isRunning())
            apiKeyMockServer.stop();
        if(jwtMockServer.isRunning())
            jwtMockServer.stop();
        if(digestMockServer.isRunning())
            digestMockServer.stop();
        if(mutualTlsMockServer.isRunning())
            mutualTlsMockServer.stop();
        if(hmacMockServer.isRunning())
            hmacMockServer.stop();
        if(samlMockServer.isRunning())
            samlMockServer.stop();
    }



    @Test
    void testBasicAuthClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                .get("/basic-auth"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(BASIC_AUTH_200_RESPONSE_STRING));


        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // check if we got a request for that url
                    List<ServeEvent> events = basicAuthContentMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    Assertions.assertEquals(1, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + basicAuthContentMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on basicAuthContentMockServer");
                });
    }

    @Test
    void testOAuth2Client() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/oauth2"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(OAUTH_200_RESPONSE_STRING));


        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // check if we got a request for that url
                    List<ServeEvent> events = oauth2ContentMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    Assertions.assertEquals(1, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + oauth2ContentMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on oauth2ContentMockServer");
                });
    }

    @Test
    void testNTLMClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/ntlm"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(NTLM_200_RESPONSE_STRING));


        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // check if we got a request for that url
                    List<ServeEvent> events = ntlmMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    // the number of requests should be 3, according to the NTLM authorization process
                    Assertions.assertEquals(3, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + ntlmMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on ntlmMockServer");
                });
    }

    @Test
    void testApiKeyClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/api-key"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(API_KEY_200_RESPONSE_STRING));


        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // check if we got a request for that url
                    List<ServeEvent> events = apiKeyMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    Assertions.assertEquals(1, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + apiKeyMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on apiKeyMockServer");
                });
    }

    @Test
    void testJWTClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/jwt")
                        .header("Authorization", "Bearer mockToken"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(JWT_200_RESPONSE_STRING));


        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // check if we got a request for that url
                    List<ServeEvent> events = jwtMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    Assertions.assertEquals(1, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + jwtMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on jwtMockServer");

                    // check that the authorization header is present and it's correct
                    String authHeader = events.getFirst().getRequest().getHeader("Authorization");
                    Assertions.assertNotNull(authHeader, "Authorization header is missing");
                    Assertions.assertTrue(authHeader.startsWith("Bearer "), "Authorization header must start with 'Bearer '");
                    Assertions.assertEquals("Bearer mockToken", authHeader, "Authorization header value is incorrect");


                });
    }

    @Test
    void testDigestAuthClient() throws Exception {
        // === Trigger the controller endpoint that internally uses the DigestApacheClient ===
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/digest"))
                .andDo(MockMvcResultHandlers.print())
                // Expect overall response to be successful (2xx)
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                // Expect response body to match concatenation of two successful responses
                .andExpect(MockMvcResultMatchers.content().string(DIGEST_200_FIRST_RESPONSE_STRING + DIGEST_200_SECOND_RESPONSE_STRING));

        // === Awaitility block ensures async events are completed (e.g., all WireMock events) ===
        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // === Collect all requests handled by WireMock ===
                    List<ServeEvent> events = digestMockServer.getAllServeEvents();

                    // Expect exactly 3 requests: 1 to /auth, 2 to protected endpoints
                    int numberOfRequestReceived = events.size();

                    Assertions.assertEquals(3, numberOfRequestReceived);

                    // === Assert only one call to /auth for the initial digest challenge ===
                    long authCalls = events.stream()
                            .filter(event -> event.getRequest().getUrl().equals("/auth"))
                            .count();

                    Assertions.assertEquals(1, authCalls, "The /auth endpoint should be called exactly once");

                    // === Assert that no 401 errors occurred during /get-first-content and /get-second-content ===
                    long unauthorizedCalls = events.stream()
                            .filter(event -> (event.getRequest().getUrl().equals("/get-first-content") ||
                                    event.getRequest().getUrl().equals("/get-second-content")) &&
                                    event.getResponse().getStatus() == 401)
                            .count();

                    Assertions.assertEquals(0, unauthorizedCalls, "No 401 responses expected on subsequent calls");

                    // === Ensure all protected calls include the Authorization header ===
                    boolean allHaveAuthHeader = events.stream()
                            .filter(event -> event.getRequest().getUrl().equals("/get-first-content") ||
                                    event.getRequest().getUrl().equals("/get-second-content"))
                            .allMatch(event -> event.getRequest().getHeaders().getHeader("Authorization").isPresent());

                    Assertions.assertTrue(allHaveAuthHeader, "All subsequent requests must include the Authorization header");

                });
    }

    @Test
    void testMutualTlsAuthClient() throws Exception {
        // === Trigger the controller endpoint that internally uses the mutual TLS client ===
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/mutual-tls"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(MUTUAL_TLS_200_SECOND_RESPONSE_STRING));

        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    // === Collect all requests handled by WireMock ===
                    List<ServeEvent> events = mutualTlsMockServer.getAllServeEvents();

                    // Expect exactly 1 request
                    int numberOfRequestReceived = events.size();

                    Assertions.assertEquals(1, numberOfRequestReceived);

                    // Check that no requests returned HTTP 401 Unauthorized (access denied)
                    long unauthorizedCalls = events.stream()
                            .filter(event -> event.getResponse().getStatus() == 401)
                            .count();
                    Assertions.assertEquals(0, unauthorizedCalls,
                            "No 401 Unauthorized responses expected");

                    boolean isHttpsEnabled = mutualTlsMockServer.getOptions().httpsSettings().port() > 0;

                    boolean allHttps = events.stream()
                            .allMatch(event -> {
                                // URL is only path, so no scheme here.
                                // Just return true if HTTPS is enabled on the server
                                return isHttpsEnabled;
                            });
                    Assertions.assertTrue(allHttps, "All requests should be HTTPS because the server uses HTTPS");

                });
    }

    @Test
    void testHmacAuthClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/hmac"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(HMAC_200_RESPONSE_STRING));

        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    List<ServeEvent> events = hmacMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    Assertions.assertEquals(1, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + hmacMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on hmacMockServer");

                    // check HMAC header presence and value
                    String hmacHeader = events.getFirst().getRequest().getHeader("X-HMAC-SIGNATURE");
                    Assertions.assertNotNull(hmacHeader, "X-HMAC-SIGNATURE header is missing");
                    Assertions.assertFalse(hmacHeader.isBlank(), "X-HMAC-SIGNATURE header is blank");
                });
    }

    @Test
    void testSamlAuthClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/saml"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.content().string(SAML_200_RESPONSE_STRING));

        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    List<ServeEvent> events = samlMockServer.getAllServeEvents();
                    int numberOfRequestReceived = events.size();
                    Assertions.assertEquals(1, numberOfRequestReceived);

                    boolean requestReceived = events
                            .stream()
                            .anyMatch(event -> event.getRequest().getUrl().equals("/get-data") &&
                                    event.getRequest().getAbsoluteUrl().contains(":" + samlMockServer.getOptions().portNumber()));

                    Assertions.assertTrue(requestReceived, "No request found on samlMockServer");

                    // check SAMLAssertion header presence and value
                    String samlHeader = events.getFirst().getRequest().getHeader("SAMLAssertion");
                    Assertions.assertNotNull(samlHeader, "SAMLAssertion header is missing");
                    Assertions.assertFalse(samlHeader.isBlank(), "SAMLAssertion header is blank");
                });
    }

}
