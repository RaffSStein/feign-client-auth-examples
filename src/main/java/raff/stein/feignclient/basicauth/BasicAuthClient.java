package raff.stein.feignclient.basicauth;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.basicauth.config.BasicAuthClientConfig;

@FeignClient(
        name = "basicAuthClient",
        url = "${spring.application.rest.client.basic-auth.host}",
        configuration = BasicAuthClientConfig.class
)
public interface BasicAuthClient {

    @GetMapping("/get-data")
    String getData();
}
