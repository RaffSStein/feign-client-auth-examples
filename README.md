# Feign Client Authentication Examples with Spring

This repository demonstrates the usage of various authentication methods when interacting with APIs using **Feign Client**
in a Spring Boot application. 
The examples are showcased into a test class which simulates servers for each auth method.

## Table of Contents

- [Overview](#overview)
- [Basic Authentication Example](#basic-authentication-example)
- [OAuth2 Authentication Example](#oauth2-authentication-example)
- [NTLM Authentication Example](#ntlm-authentication-example)
- [API Key Authentication Example](#api-key-authentication-example)
- [JWT Based Authentication Example](#jwt-based-authentication-example)
- [Digest Authentication Example](#digest-authentication-example)
- [Mutual TLS Authentication Example](#mutual-tls-authentication-example)
- [HMAC (Hash-based Message Authentication Code) Example](#hmac-hash-based-message-authentication-code-example)
- [SAML (Security Assertion Markup Language) Example](#saml-security-assertion-markup-language-example)

[//]: # (- [How to Run the Project]&#40;#how-to-run-the-project&#41;)

[//]: # (- [Configuration]&#40;#configuration&#41;)

[//]: # (- [License]&#40;#license&#41;)

## Overview

In this project, we showcase the configuration and use of the following authentication methods with **Feign Client**:

1. **Basic Authentication**:
Basic authentication is a simple authentication scheme built into the HTTP protocol. In this example, 
a Feign Client is configured to send a username and password in the `Authorization` header in the form of `Basic base64(username:password)`.

2. **OAuth2 Authentication**:
OAuth2 is a more robust authorization framework. In this example, we configure Feign Client to use OAuth2 tokens 
to authenticate API requests, using `Spring Security` to handle `OAuth2 token` generation and validation.

3. **NTLM Authentication**:
NTLM uses a three-step handshake (challenge-response mechanism) that involves sending and managing dynamically encoded messages
in order to authenticate into the server.
``org.apache.http`` library is used in order to build a custom ``Client`` which handles this authorization method

4. **API Key Authentication**:
API Key authentication involves including a static key with each API request. The key can be sent via a header, a query parameter, or a cookie.

5. **JWT Based Authentication**:
***JSON Web Tokens (JWT)*** are self-contained tokens that include encoded claims and are digitally signed (using either symmetric or asymmetric keys).
In this setup, the Feign `Client` sends the JWT in the `Authorization` header received in the original API call to the underlying system.

6. **Digest Authentication**:
Digest authentication improves upon Basic Authentication by using a challenge–response mechanism where the credentials 
are hashed along with a nonce (a random value) before being sent.

7. **Mutual TLS Authentication**:
Mutual TLS authentication involves both the client and the server authenticating each other using digital certificates during the SSL/TLS handshake.

8. **HMAC (Hash-based Message Authentication Code)**:
HMAC authentication relies on a shared `secret key` between the client and server. The client computes a hash (signature) 
of the request data (which can include headers, query parameters, or the payload) and sends it along with the request. 
The server then recomputes the hash to verify the request's integrity and authenticity.

9. **SAML (Security Assertion Markup Language)**:
SAML is an XML-based protocol often used for Single Sign-On (SSO) in enterprise environments. 
It enables the exchange of authentication and authorization data between an identity provider and a service provider.


## Basic Authentication Example

Basic Authentication sends the username and password encoded in base64 as part of the request's `Authorization` header.

### Feign Client Configuration (Basic Auth)
To configure Basic authentication in Feign Client, we need to add a `RequestInterceptor` that includes the username and password
(encoded) in the **Authorization** header of each request.
In the example, the credentials are properties.


```java
public class BasicAuthClientConfig {

   @Value("${spring.application.rest.client.basic-auth.username}")
   private String username;
   @Value("${spring.application.rest.client.basic-auth.password}")
   private String password;

   @Bean
   public RequestInterceptor basicAuthRequestInterceptor() {
      return requestTemplate -> {
         // compose the auth string in the format: "username:password"
         final String auth = username + ":" + password;
         // encode it
         final String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
         // and pass it as an Authorization header
         requestTemplate.header("Authorization", "Basic " + encodedAuth);
      };
   }
}
```


## OAuth2 Authentication Example

OAuth2 Authentication is a widely used standard for access delegation. It allows clients to access resources on behalf of a user or a service by obtaining an access token and using it in the `Authorization` header of API requests.

In this example, we will configure a Feign client to make requests using OAuth2 authentication.

### Feign Client Configuration (OAuth2)

To configure OAuth2 authentication in Feign Client, we need to add a `OAuth2AccessTokenInterceptor` that includes the
OAuth2 client id, the OAuth2 client secre and the token uri.
The implementation was done with a `ClientRegistration` object, which enables your app to be registered without
taking care of any JWT or refresh tokens.


```java
public class OAuth2ClientConfig {


    @Bean
    public OAuth2AccessTokenInterceptor oAuth2AccessTokenInterceptor(
            @Value("${spring.application.name}") String appName,
            @Value("${spring.application.rest.client.oauth2.token.url}") String tokenUri,
            @Value("${spring.application.rest.client.oauth2.token.client-id}") String clientId,
            @Value("${spring.application.rest.client.oauth2.token.client-secret}") String clientSecret) {

        final ClientRegistration clientRegistration = ClientRegistration
                // the registration ID will be our app name
                .withRegistrationId(appName)
                .clientId(clientId)
                .clientSecret(clientSecret)
                // in this example, we are using the client credentials type (but there are more, check the
                // org.springframework.security.oauth2.client.registration for more)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // with POST auth method
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .tokenUri(tokenUri)
                .build();

        // construct the repository with our client registration
        final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository =
                new InMemoryClientRegistrationRepository(clientRegistration);

        // use the service in order to store the client registration in memory
        final InMemoryOAuth2AuthorizedClientService inMemoryOAuth2AuthorizedClientService =
                new InMemoryOAuth2AuthorizedClientService(inMemoryClientRegistrationRepository);

        return new OAuth2AccessTokenInterceptor(
                appName,
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        inMemoryClientRegistrationRepository,
                        inMemoryOAuth2AuthorizedClientService)
        );
    }

    @Bean
    public Logger.Level feignLoggerLevel() {return Logger.Level.FULL;}

}
```

## NTLM Authentication Example

NTLM uses a three-step handshake (challenge-response mechanism) that involves sending and managing dynamically encoded messages. 
1. The client sends an initial request without an authentication header. The server detects the absence of credentials and responds with a 401 Unauthorized status, including the following header in the response:
``WWW-Authenticate: NTLM``.
This indicates that the server requires NTLM authentication.
2. After receiving the 401 response, the client generates an NTLM negotiation message (Type 1), which is Base64-encoded, and sends a new request with the following header:
``Authorization: NTLM <type1_message_in_base64>``
3. The server responds with another 401 Unauthorized, but this time it includes a challenge in the header:
``WWW-Authenticate: NTLM <challenge_in_base64>``. The server provides a challenge that the client must process.
4. The client takes the challenge received, along with the credentials (username, password, domain, etc.), and generates the NTLM response message (Type 3). This response is also Base64-encoded and sent in a new request with the following header:
``Authorization: NTLM <type3_message_in_base64>``.
If the server successfully verifies the response, the request is accepted (typically returning a 200 OK).
  
In this example, we will configure a Feign client to make requests using NTLM authentication.
But be careful: this authentication method is deprecated and a more solid authentication should be used (like Basic Auth).

### Feign Client Configuration (NTLM)
For NTLM authentication we've defined a new Feign (ApacheHttp) Client.
For this kind of client we used the ``org.apache.http`` library in order to define some characteristics of the client, like:
1. Credentials/Credentials provider
2. SSL for HTTPS calls
3. Client definition, including any custom headers



```java
public class NTLMClientConfig {

    @Value("${spring.application.rest.client.ntlm.username}")
    private String username;
    @Value("${spring.application.rest.client.ntlm.password}")
    private String password;
    @Value("${spring.application.rest.client.ntlm.workstation}")
    private String workstation;
    @Value("${spring.application.rest.client.ntlm.domain}")
    private String domain;

    @Bean
    public Client NTLMClient() {
        try {
            // NTLM credentials definition
            final NTCredentials ntCredentials = new NTCredentials(
                    username,
                    password,
                    workstation,
                    domain);

            final BasicCredentialsProvider basicCredentialsProvider = new BasicCredentialsProvider();
            basicCredentialsProvider.setCredentials(AuthScope.ANY, ntCredentials);

            // configure SSL for HTTPS calls if needed
            final SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();
            sslContextBuilder.loadTrustMaterial(new TrustSelfSignedStrategy());
            final SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
                    sslContextBuilder.build(),
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier());

            // HTTP client definition
            final CloseableHttpClient closeableHttpClient = HttpClients.custom()
                    .setDefaultCredentialsProvider(basicCredentialsProvider)
                    //SSL
                    .setSSLSocketFactory(sslConnectionSocketFactory)
                    // any custom headers
                    .setDefaultHeaders(List.of(
                            new BasicHeader("custom-header", "customheader")
                    ))
                    .build();

            return new ApacheHttpClient(closeableHttpClient);

        } catch (Exception e) {
            throw new RuntimeException("Error during NTLM feign client definition", e);
        }
    }

    @Bean
    public Logger.Level ntlmLoggerLevel() {return Logger.Level.FULL;}
}
```

## API Key Authentication Example
**API key authentication** is a straightforward method for controlling access to an API. Here's how it works:

1. **Issuance of the API Key**:
A unique key is generated and provided to the client (e.g., an application or developer). This key acts as a credential 
that identifies and authorizes the client.

2. **Including the API Key in Requests**:
The client includes the API key with every API request. Typically, this is done by adding it to an HTTP header 
(commonly named something like X-API-KEY), although it can also be transmitted as a query parameter or, less commonly, in a cookie.

3. **Server-Side Verification**:
When the server receives a request, it extracts the API key from the header (or other location) and verifies it against
a list of valid keys. If the key is valid, the server processes the request; if not, it returns an error 
(often a 401 Unauthorized or 403 Forbidden).

### Feign Client Configuration (API Key)

To configure the Api-Key authentication in Feign Client, we need to add a `RequestInterceptor` that basically
adds a custom header to our request, representing our API key for the API call.

```java
public class ApiKeyClientConfig {

    @Value("${spring.application.rest.client.api-key.key}")
    private String apiKey;

    @Bean
    public RequestInterceptor apiKeyRequestInterceptor() {
        return requestTemplate -> {
            // just pass the APIKey as header
            requestTemplate.header("X-API-KEY", apiKey);
        };
    }

    @Bean
    public Logger.Level apiKeyAuthLoggerLevel() {return Logger.Level.FULL;}
}
```

## JWT Based Authentication Example
JWT (JSON Web Token) authentication is a widely adopted method for securely transmitting information between parties as a JSON object. JWTs are commonly used for authorization, where the token is issued by an authentication server and then used by clients to access protected resources.
How it Works:
1. **Token Issuance**: 
The client authenticates (e.g., using credentials) with an Authorization Server, which issues a signed JWT.
This token contains claims (such as user identity and roles) and is cryptographically signed to prevent tampering.

2. **Token Forwarding**:
For each subsequent request to protected resources, the client includes the JWT in the HTTP Authorization header, using the Bearer schema:
``Authorization: Bearer <your-jwt-token>``

3. **Server Verification**:
The receiving server verifies the JWT’s signature, expiration time, and claims to ensure the token is valid and trusted.
If valid, access is granted; otherwise, a ``401 Unauthorized`` response is returned.

### Feign Client Configuration (JWT)
In this example, we assume that our Spring Boot application receives a request that already includes a valid ``Authorization: Bearer <token>`` header.
We want our Feign client to forward this JWT to the downstream service so that it can perform its own authorization checks.

To achieve this, we define a ``RequestInterceptor`` that extracts the JWT from the incoming HTTP request and sets it in the outgoing Feign call:
```java
public class JwtClientConfig {

    // the client will forward the JWT token received in the API request to the underlying system
    // which, we suppose, will have an auth check on its side
    @Bean
    public RequestInterceptor jwtForwardingInterceptor() {
        return requestTemplate -> {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes == null) return;

            HttpServletRequest request = attributes.getRequest();
            String authorizationHeader = request.getHeader("Authorization");

            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                requestTemplate.header("Authorization", authorizationHeader);
            }
        };
    }
}

```
## Digest Authentication Example
**Digest Authentication** is a challenge-response mechanism defined by ***RFC 7616***, where the client proves knowledge of a
password without sending it in plaintext. It's a more secure alternative to Basic Auth, as it protects credentials using
hashing and nonce-based mechanisms.
How it Works:
1. **Initial Challenge:**
The client makes an unauthenticated request to the server. The server responds with a ``401 Unauthorized`` status and a
``WWW-Authenticate`` header containing the digest challenge (realm, nonce, opaque, etc.).

2. **Digest Response:**
The client computes a hash (digest) of the username, password, and challenge parameters, and resends the request with
an ``Authorization: Digest ...`` header containing the computed response.

3. **Authentication Success:**
The server verifies the digest response. If valid, it returns a ``200 OK`` and the requested resource. 
Otherwise, another ``401`` is issued.

### Implementation Notes:
- In this example, we do not use a Feign client because Apache HttpClient provides more precise control over the
Digest scheme negotiation.

- The client initializes a ``DigestScheme`` using the first ``401`` response and then reuses this authentication context
``(HttpClientContext)`` across subsequent requests using an ``AuthCache``.

- This avoids redundant challenge-response handshakes after the first authenticated request.

### Apache HttpClient Configuration
Here's the key part of the implementation (simplified):
```java
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
```
Then, a first unauthenticated request is performed explicitly to force the ``401 Unauthorized``, and the server's 
challenge is processed manually:
```java
DigestScheme digestScheme = new DigestScheme();
digestScheme.processChallenge(wwwAuthHeaderFrom401);

AuthCache authCache = new BasicAuthCache();
authCache.put(targetHost, digestScheme);

HttpClientContext context = HttpClientContext.create();
context.setAuthCache(authCache);
```
Finally, this context is reused in all subsequent authenticated requests:
```java
httpClient.execute(targetHost, request, reusableContext);
```

## Mutual TLS Authentication Example
**Mutual TLS (mTLS)** is an extension of standard TLS in which both client and server authenticate each other using certificates.
This enhances security by ensuring that not only the server is trusted by the client, but the client is also verified by 
the server — enabling strong identity verification and secure communication. How it Works:
1. **TLS Handshake Initialization:**
The client initiates a secure connection over ``HTTPS``. The server responds with its certificate, as in standard ``TLS``.

2. **Client Certificate Request:**
Since mTLS is enabled, the server requests a certificate from the client.

3. **Client Authentication:**
The client sends its certificate (signed by a trusted CA or self-signed for testing), proving its identity.

4. **Verification:**
The server verifies the client certificate against its truststore. If valid, the ``TLS`` handshake completes.

5. **Secure Communication:**
Once mutual authentication succeeds, encrypted communication continues over the established TLS session.

### Implementation Notes:

In this example, we configure a ``WireMock`` server with:

- A keystore containing its private key and certificate. 
- A truststore to validate the client certificate. 
- Client authentication explicitly required via ``needClientAuth(true)``.

On the client side, we configure the ``Feign HTTP client`` with:
- A truststore to validate the server certificate. 
- A keystore with the client's own certificate for mutual authentication.

### WireMock Configuration (Server Side)
```java
mutualTlsMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
    .httpsPort(8089)
    .needClientAuth(true)
    .trustStorePath("server-truststore.jks")
    .trustStorePassword("changeit")
    .trustStoreType("PKCS12")
    .keystorePath("server-keystore.jks")
    .keystorePassword("changeit")
    .keystoreType("PKCS12")
);
mutualTlsMockServer.start();
```

### Feign Client Configuration (Client Side)
The client HTTP configuration is built using Apache ``HttpClient``, enabling ``SS``L context with both keystore and truststore:
```java
SSLContext sslContext = SSLContexts.custom()
    .loadTrustMaterial(truststorePath, truststorePassword.toCharArray())
    .loadKeyMaterial(keystorePath, keystorePassword.toCharArray(), keystorePassword.toCharArray())
    .build();

SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
CloseableHttpClient httpClient = HttpClients.custom()
    .setSSLSocketFactory(socketFactory)
    .build();
```
Then, this client is injected into a Feign builder:
```java
Feign.builder()
    .client(new ApacheHttpClient(httpClient))
    .target(MutualTlsClient.class, "https://localhost:8089");
```
### Test Scenario
- The test performs a ``GET /get-data`` request using the mTLS-enabled ``Feign client``. 
- The WireMock server is configured to require and validate the client certificate. 
- If mutual authentication succeeds, the server returns a ``200 OK`` and a stubbed response body.

## HMAC (Hash-based Message Authentication Code) Example

#### WIP



## SAML (Security Assertion Markup Language) Example

#### WIP

 