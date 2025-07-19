package raff.stein.feignclient.client.saml.config;

import feign.Logger;
import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

/**
 * Feign configuration for SAML authentication.
 * Adds a SAML assertion as a custom header.
 */
public class SAMLClientConfig {

    @Value("${spring.application.rest.client.saml.saml-assertion}")
    private String samlAssertion;

    @Bean
    public RequestInterceptor samlRequestInterceptor() {
        return requestTemplate -> {
            // Add the SAML assertion as a header (commonly "SAMLAssertion" or "Authorization: SAML ...")
            requestTemplate.header("SAMLAssertion", samlAssertion);
        };
    }

    @Bean
    public Logger.Level samlLoggerLevel() {
        return Logger.Level.FULL;
    }
}
