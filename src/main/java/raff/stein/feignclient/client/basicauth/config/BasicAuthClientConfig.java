package raff.stein.feignclient.client.basicauth.config;

import feign.Logger;
import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import java.util.Base64;

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

    @Bean
    public Logger.Level basicAuthLoggerLevel() {return Logger.Level.FULL;}
}
