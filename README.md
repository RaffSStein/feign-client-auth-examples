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
- [Mutual TLS Authentication Example](#digest-authentication-example)
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
If valid, access is granted; otherwise, a 401 Unauthorized response is returned.

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

#### WIP


## Mutual TLS Authentication Example

#### WIP



## HMAC (Hash-based Message Authentication Code) Example

#### WIP



## SAML (Security Assertion Markup Language) Example

#### WIP

