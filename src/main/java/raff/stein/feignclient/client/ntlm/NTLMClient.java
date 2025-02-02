package raff.stein.feignclient.client.ntlm;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import raff.stein.feignclient.client.ntlm.config.NTLMClientConfig;

@FeignClient(
        name = "NTLMClient",
        url = "${spring.application.rest.client.ntlm.host}",
        configuration = NTLMClientConfig.class
)
public interface NTLMClient {

    @GetMapping("/get-data")
    String getData();
}
