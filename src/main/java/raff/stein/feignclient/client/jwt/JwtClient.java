package raff.stein.feignclient.client.jwt;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.jwt.config.JwtClientConfig;

@FeignClient(
        name = "jwtClient",
        url = "${spring.application.rest.client.jwt.host}",
        configuration = JwtClientConfig.class
)
public interface JwtClient {

    @GetMapping("/get-data")
    String getData();
}
