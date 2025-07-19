package raff.stein.feignclient.client.saml;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.saml.config.SAMLClientConfig;

@FeignClient(
        name = "samlClient",
        url = "${spring.application.rest.client.saml.host}",
        configuration = SAMLClientConfig.class
)
public interface SAMLClient {
    @GetMapping("/get-data")
    String getData();
}
