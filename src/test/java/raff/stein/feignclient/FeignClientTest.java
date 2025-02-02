package raff.stein.feignclient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.openfeign.security.OAuth2AccessTokenInterceptor;
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

    OAuth2AccessTokenInterceptor oAuth2AccessTokenInterceptor = Mockito.mock(OAuth2AccessTokenInterceptor.class);


    // BASIC AUTH
    // specific basic auth API calls
    static WireMockServer basicAuthContentMockServer;

    // OAUTH
    // one client for oauth2 auth only
    static WireMockServer oauth2AuthMockServer;
    // one for specific oauth2 API calls
    static WireMockServer oauth2ContentMockServer;

    @BeforeAll
    static void beforeAll() {
        setupBasicAuthServers();
        setupOauth2Servers();
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
                                .withStatus(200))
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
                                .withStatus(200))
        );
    }

    @Test
    void testBasicAuthClient() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                .get("/basic-auth"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());


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
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());


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
}
