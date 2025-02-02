package raff.stein.feignclient.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import raff.stein.feignclient.basicauth.BasicAuthClient;
import raff.stein.feignclient.oauth2client.OAuth2Client;

@Service
@Slf4j
@RequiredArgsConstructor
public class FeignClientSimpleService {

    private final BasicAuthClient basicAuthClient;
    private final OAuth2Client oAuth2Client;

    public String simpleBasicAuthClientCall() {
        return basicAuthClient.getData();
    }

    public String simpleOAuth2ClientCall() {
        return oAuth2Client.getData();
    }
}
