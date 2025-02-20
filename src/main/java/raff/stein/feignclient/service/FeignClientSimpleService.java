package raff.stein.feignclient.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import raff.stein.feignclient.client.apikey.ApiKeyClient;
import raff.stein.feignclient.client.basicauth.BasicAuthClient;
import raff.stein.feignclient.client.ntlm.NTLMClient;
import raff.stein.feignclient.client.oauth2.OAuth2Client;

@Service
@Slf4j
@RequiredArgsConstructor
public class FeignClientSimpleService {

    private final BasicAuthClient basicAuthClient;
    private final OAuth2Client oAuth2Client;
    private final NTLMClient ntlmClient;
    private final ApiKeyClient apiKeyClient;

    public String simpleBasicAuthClientCall() {
        return basicAuthClient.getData();
    }

    public String simpleOAuth2ClientCall() {
        return oAuth2Client.getData();
    }

    public String simpleNTLMClientCall() {
        return ntlmClient.getData();
    }

    public String simpleApiKeyClientCall() {
        return apiKeyClient.getData();
    }

}
