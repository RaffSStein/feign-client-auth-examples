package raff.stein.feignclient.client.hmac.config;

import feign.Logger;
import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class HashBasedMessageAuthClientConfig {

    @Value("${spring.application.rest.client.hmac.secret}")
    private String secret;

    @Bean
    public RequestInterceptor hmacRequestInterceptor() {
        return requestTemplate -> {
            try {
                String data = requestTemplate.method() + requestTemplate.url();
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
                String signature = Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
                requestTemplate.header("X-HMAC-SIGNATURE", signature);
            } catch (Exception e) {
                throw new RuntimeException("Error during HMAC sign generation", e);
            }
        };
    }

    @Bean
    public Logger.Level hashBasedMessageAuthLoggerLevel() {return Logger.Level.FULL;}
}
