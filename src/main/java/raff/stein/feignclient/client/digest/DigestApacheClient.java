package raff.stein.feignclient.client.digest;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.auth.DigestSchemeFactory;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@Component
public class DigestApacheClient {

    private final CloseableHttpClient httpClient;
    private final String baseUrl;
    private final HttpHost targetHost;
    private final HttpClientContext reusableContext;

    /**
     * Constructor that sets up the Apache HTTP client to support Digest Authentication.
     * This includes:
     * - Extracting the host and port from the base URL.
     * - Configuring the CredentialsProvider with username and password.
     * - Registering the Digest authentication scheme.
     * - Pre-authenticating once to cache the Digest scheme and reuse it for future requests.
     */
    public DigestApacheClient(
            @Value("${spring.application.rest.client.digest-auth.host}") String baseUrl,
            @Value("${spring.application.rest.client.digest-auth.username}") String username,
            @Value("${spring.application.rest.client.digest-auth.password}") String password) {

        this.baseUrl = baseUrl;
        // post and host extraction from URI
        URI uri;
        try {
            uri = new URI(baseUrl);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid base URL: " + baseUrl, e);
        }

        String host = uri.getHost();
        int port = (uri.getPort() != -1) ? uri.getPort() : ("https".equals(uri.getScheme()) ? 443 : 80);
        this.targetHost = new HttpHost(host, port, uri.getScheme());
        // Provides the credentials (username and password) for a specific AuthScope
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
                new AuthScope(host, port),
                new UsernamePasswordCredentials(username, password)
        );
        // Register the Digest authentication scheme (needed explicitly)
        Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                .register(AuthSchemes.DIGEST, new DigestSchemeFactory())
                .build();
        // Build the HTTP client with the credentials and scheme
        this.httpClient = HttpClients.custom()
                .setDefaultCredentialsProvider(credentialsProvider)
                .setDefaultAuthSchemeRegistry(authSchemeRegistry)
                .build();

        // Force an initial 401 challenge to extract the DigestScheme and cache it
        this.reusableContext = preAuthenticate();
    }

    /**
     * Performs an initial HTTP call (without credentials) to force a 401 response.
     * This response contains the Digest challenge in the WWW-Authenticate header.
     * The DigestScheme is extracted and stored in an AuthCache, which is later reused
     * to avoid repeating the 401 round-trip on each request.
     *
     * @return HttpClientContext containing the cached DigestScheme
     */
    private HttpClientContext preAuthenticate() {
        // Creates a no-credential client in order to force the 401
        try (CloseableHttpClient noCredentialClient = HttpClients.createDefault()) {
            // unauthorized request to a specified endpoint
            HttpGet unauthorizedRequest = new HttpGet(baseUrl + "/auth");
            // empty context
            HttpClientContext context = HttpClientContext.create();
            try (CloseableHttpResponse response = noCredentialClient.execute(targetHost, unauthorizedRequest, context)) {
                if (response.getStatusLine().getStatusCode() == 401) {
                    Header wwwAuth = response.getFirstHeader("WWW-Authenticate");
                    if (wwwAuth != null && wwwAuth.getValue().startsWith(AuthSchemes.DIGEST)) {
                        // Parse the WWW-Authenticate challenge into a DigestScheme
                        DigestScheme digestScheme = new DigestScheme();
                        digestScheme.processChallenge(wwwAuth);
                        // Cache the DigestScheme so it can be reused automatically
                        AuthCache authCache = new BasicAuthCache();
                        authCache.put(targetHost, digestScheme);
                        // insert it into the context, so it can be reused from the next api calls
                        HttpClientContext authContext = HttpClientContext.create();
                        authContext.setAuthCache(authCache);
                        return authContext;
                    }
                } else {
                    throw new RuntimeException("Expected 401 but got " + response.getStatusLine().getStatusCode());
                }
            }
        } catch (IOException | MalformedChallengeException e) {
            throw new RuntimeException("Failed to initialize Digest auth context", e);
        }
        throw new RuntimeException("Digest challenge was not received from the server");
    }


    public String getFirstContent() {
        HttpGet request = new HttpGet(baseUrl + "/get-first-content");

        try (CloseableHttpResponse response = httpClient.execute(targetHost, request, reusableContext)) {
            int status = response.getStatusLine().getStatusCode();
            if (status == 200) {
                return EntityUtils.toString(response.getEntity());
            } else {
                throw new RuntimeException("HTTP error: " + status);
            }
        } catch (IOException e) {
            throw new RuntimeException("Error during HTTP Digest call: " + e.getMessage(), e);
        }
    }

    public String getSecondContent() {
        HttpGet request = new HttpGet(baseUrl + "/get-second-content");

        try (CloseableHttpResponse response = httpClient.execute(targetHost, request, reusableContext)) {
            int status = response.getStatusLine().getStatusCode();
            if (status == 200) {
                return EntityUtils.toString(response.getEntity());
            } else {
                throw new RuntimeException("HTTP error: " + status);
            }
        } catch (IOException e) {
            throw new RuntimeException("Error during HTTP Digest call: " + e.getMessage(), e);
        }
    }


}
