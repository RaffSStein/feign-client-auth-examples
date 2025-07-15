package raff.stein.feignclient.client.mutualtls;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.mutualtls.config.MutualTlsClientConfig;

@FeignClient(
        name = "mutualTlsClient",
        url = "${spring.application.rest.client.mutual-tls.host}",
        configuration = MutualTlsClientConfig.class)
public interface MutualTlsClient {

    @GetMapping("/get-data")
    String getData();
}
