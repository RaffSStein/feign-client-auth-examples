package raff.stein.feignclient.client.apikey.config;

import feign.Logger;
import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

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
    public Logger.Level basicAuthLoggerLevel() {return Logger.Level.FULL;}
}
