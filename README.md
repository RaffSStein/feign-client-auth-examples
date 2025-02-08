# Feign Client Authentication Examples with Spring

This repository demonstrates the usage of various authentication methods when interacting with APIs using **Feign Client** in a Spring Boot application. The examples in this project show how to configure and use **Basic Authentication** and **OAuth2 Authentication** for making secure API requests.

## Table of Contents

- [Overview](#overview)
- [Basic Authentication Example](#basic-authentication-example)
- [OAuth2 Authentication Example](#oauth2-authentication-example)
- [NTLM Authentication Example](#ntlm-authentication-example)

[//]: # (- [How to Run the Project]&#40;#how-to-run-the-project&#41;)

[//]: # (- [Configuration]&#40;#configuration&#41;)

[//]: # (- [License]&#40;#license&#41;)

## Overview

In this project, we showcase the configuration and use of two popular authentication methods with **Feign Client**:

1. **Basic Authentication**:
   Basic authentication is a simple authentication scheme built into the HTTP protocol. In this example, a Feign Client is configured to send a username and password in the `Authorization` header in the form of `Basic base64(username:password)`.

2. **OAuth2 Authentication**:
   OAuth2 is a more robust authorization framework. In this example, we configure Feign Client to use OAuth2 tokens to authenticate API requests, using Spring Security to handle OAuth2 token generation and validation.

Both examples demonstrate how to create a custom Feign Client configuration to include the necessary authentication information in the request headers.

## Basic Authentication Example

Basic Authentication sends the username and password encoded in base64 as part of the request's `Authorization` header.

### Feign Client Configuration (Basic Auth)
To configure Basic authentication in Feign Client, we need to add a RequestInterceptor that includes the username and password
(encoded) in the Authorization header of each request.
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
