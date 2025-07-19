package raff.stein.feignclient.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import raff.stein.feignclient.client.apikey.ApiKeyClient;
import raff.stein.feignclient.client.basicauth.BasicAuthClient;
import raff.stein.feignclient.client.digest.DigestApacheClient;
import raff.stein.feignclient.client.hmac.HashBasedMessageAuthClient;
import raff.stein.feignclient.client.jwt.JwtClient;
import raff.stein.feignclient.client.mutualtls.MutualTlsClient;
import raff.stein.feignclient.client.ntlm.NTLMClient;
import raff.stein.feignclient.client.oauth2.OAuth2Client;
import raff.stein.feignclient.client.saml.SAMLClient;

@Service
@Slf4j
@RequiredArgsConstructor
public class FeignClientSimpleService {

    private final BasicAuthClient basicAuthClient;
    private final OAuth2Client oAuth2Client;
    private final NTLMClient ntlmClient;
    private final ApiKeyClient apiKeyClient;
    private final JwtClient jwtClient;
    private final DigestApacheClient digestApacheClient;
    private final MutualTlsClient mutualTlsClient;
    private final HashBasedMessageAuthClient hashBasedMessageAuthClient;
    private final SAMLClient samlClient;

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

    public String simpleJwtClientCall() {
        return jwtClient.getData();
    }

    public String simpleDigestClientCall() {
        String firstResult = digestApacheClient.getFirstContent();
        String secondResult = digestApacheClient.getSecondContent();
        return firstResult + secondResult;
    }

    public String simpleMutualTlsClientCall() {
        return mutualTlsClient.getData();
    }

    public String simpleHashBasedMessageAuthClientCall() {
        return hashBasedMessageAuthClient.getData();
    }

    public String simpleSamlClientCall() {
        return samlClient.getData();
    }

}
