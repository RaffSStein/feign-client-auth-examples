package raff.stein.feignclient.client.apikey;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.apikey.config.ApiKeyClientConfig;

@FeignClient(
        name = "apiKeyClient",
        url = "${spring.application.rest.client.api-key.host}",
        configuration = ApiKeyClientConfig.class
)
public interface ApiKeyClient {

    @GetMapping("/get-data")
    String getData();
}
