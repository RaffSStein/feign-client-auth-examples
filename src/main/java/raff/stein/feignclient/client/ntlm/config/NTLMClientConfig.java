package raff.stein.feignclient.client.ntlm.config;

import feign.Client;
import feign.httpclient.ApacheHttpClient;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class NTLMClientConfig {

    @Value("${spring.application.rest.client.ntlm.username}")
    private String username;
    @Value("${spring.application.rest.client.ntlm.password}")
    private String password;
    @Value("${spring.application.rest.client.ntlm.workstation}")
    private String workstation;
    @Value("${spring.application.rest.client.ntlm.domain}")
    private String domain;

    @Bean
    public Client NTLMClient() {
        try {
            // NTLM credentials definition
            final NTCredentials ntCredentials = new NTCredentials(
                    username,
                    password,
                    workstation,
                    domain);

            final BasicCredentialsProvider basicCredentialsProvider = new BasicCredentialsProvider();
            basicCredentialsProvider.setCredentials(AuthScope.ANY, ntCredentials);

            // configure SSL for HTTPS calls if needed
            final SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();
            sslContextBuilder.loadTrustMaterial(new TrustSelfSignedStrategy());
            final SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
                    sslContextBuilder.build(),
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier());

            // HTTP client definition
            final CloseableHttpClient closeableHttpClient = HttpClients.custom()
                    .setDefaultCredentialsProvider(basicCredentialsProvider)
                    //SSL
                    .setSSLSocketFactory(sslConnectionSocketFactory)
                    // any custom headers
                    .setDefaultHeaders(List.of(
                            new BasicHeader("custom-header", "customheader")
                    ))
                    .build();

            return new ApacheHttpClient(closeableHttpClient);

        } catch (Exception e) {
            throw new RuntimeException("Error during NTLM feign client definition", e);
        }
    }
}
