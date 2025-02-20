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
public class FeignClientTest {

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


    private static final String BASIC_AUTH_200_RESPONSE_STRING = "Basic auth response content";
    private static final String OAUTH_200_RESPONSE_STRING = "OAuth2 response content";
    private static final String NTLM_200_RESPONSE_STRING = "NTLM response content";
    private static final String API_KEY_200_RESPONSE_STRING = "API KEY response content";


    @BeforeAll
    static void beforeAll() {
        setupBasicAuthServers();
        setupOauth2Servers();
        setupNTLMServer();
        setupAPIKeyServer();
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
}
