package raff.stein.feignclient.client.oauth2;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.oauth2.config.OAuth2ClientConfig;

@FeignClient(
        name = "OAuth2Client",
        url = "${spring.application.rest.client.oauth2.host}",
        configuration = OAuth2ClientConfig.class
)
public interface OAuth2Client {

    @GetMapping("/get-data")
    String getData();
}
