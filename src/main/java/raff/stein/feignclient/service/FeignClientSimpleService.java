package raff.stein.feignclient.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import raff.stein.feignclient.basicauth.BasicAuthClient;

@Service
@Slf4j
@RequiredArgsConstructor
public class FeignClientSimpleService {

    private final BasicAuthClient basicAuthClient;

    public String simpleBasicAuthClientCall() {
        return basicAuthClient.getData();
    }
}
