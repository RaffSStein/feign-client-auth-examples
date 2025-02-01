package raff.stein.feignclient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.shaded.org.awaitility.Awaitility;
import raff.stein.feignclient.basicauth.BasicAuthClient;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
public class BasicAuthClientTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private BasicAuthClient basicAuthClient;

    // one client for auth only
    static WireMockServer basicAuthMockServer;
    // one for specific API calls
    static WireMockServer basicAuthContentMockServer;

    @BeforeAll
    static void beforeAll() {
        setupBasicAuthMockServer();
        setupBasicAuthContentMockServer();
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

    private static void setupBasicAuthMockServer() {
        basicAuthMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(8082));
        basicAuthMockServer.start();
        basicAuthMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo("/")).willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withHeader("Content-type", "application/json")
                                .withHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                                .withBody("{ \"message\": \"Authenticated successfully!\" }")
                )
        );

        basicAuthMockServer.stubFor(
                WireMock.get(
                        WireMock.urlEqualTo("/")
                ).willReturn(
                        WireMock.aResponse()
                                .withStatus(401)
                                .withHeader("Content-type", "application/json")
                                .withHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                                .withBody("{ \"error\": \"Unauthorized\" }")
                )
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
                .untilAsserted(() -> basicAuthContentMockServer.verify(WireMock.getRequestedFor(WireMock.urlEqualTo("/get-data"))));
    }
}
