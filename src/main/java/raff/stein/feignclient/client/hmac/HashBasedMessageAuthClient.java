package raff.stein.feignclient.client.hmac;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.hmac.config.HashBasedMessageAuthClientConfig;

@FeignClient(
        name = "hashBasedMessageAuthClient",
        url = "${spring.application.rest.client.hmac.host}",
        configuration = HashBasedMessageAuthClientConfig.class)
public interface HashBasedMessageAuthClient {

    @GetMapping("/get-data")
    String getData();
}
