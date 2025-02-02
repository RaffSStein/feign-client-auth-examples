# Feign Client Authentication Examples

This repository demonstrates the usage of various authentication methods when interacting with APIs using **Feign Client** in a Spring Boot application. The examples in this project show how to configure and use **Basic Authentication** and **OAuth2 Authentication** for making secure API requests.

## Table of Contents

- [Overview](#overview)
- [Basic Authentication Example](#basic-authentication-example)
- [OAuth2 Authentication Example](#oauth2-authentication-example)
- [How to Run the Project](#how-to-run-the-project)
- [Configuration](#configuration)
- [License](#license)

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
@Configuration
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
@Configuration
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

