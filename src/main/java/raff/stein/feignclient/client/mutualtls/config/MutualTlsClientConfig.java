package raff.stein.feignclient.client.mutualtls.config;

import feign.Client;
import feign.Logger;
import feign.httpclient.ApacheHttpClient;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;

public class MutualTlsClientConfig {

    // Path to the client keystore file (PKCS#12 or JKS), which contains the client's private key and certificate.
    @Value("${spring.application.rest.client.mutual-tls.ssl.keystore.path}")
    private String keyStorePath;

    // Password protecting the client keystore. Used to unlock and retrieve the client certificate.
    @Value("${spring.application.rest.client.mutual-tls.ssl.keystore.password}")
    private String keyStorePassword;

    // Path to the truststore file, containing trusted CA certificate(s) for server verification.
    @Value("${spring.application.rest.client.mutual-tls.ssl.truststore.path}")
    private String trustStorePath;

    // Password protecting the truststore. Used to load and verify server certificates.
    @Value("${spring.application.rest.client.mutual-tls.ssl.truststore.password}")
    private String trustStorePassword;

    /**
     * Defines a Feign Client that uses Apache HttpClient configured for mutual TLS.
     * The SSLContext is initialized with both client identity (for client cert) and trust material (for server cert).
     */
    @Bean
    public Client feignClient() throws Exception {
        SSLContext sslContext = buildSslContext();
        HttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();
        return new ApacheHttpClient(httpClient);
    }

    /**
     * Constructs an SSLContext initialized for mutual TLS:
     * - keyStore: provides client-side certificate and private key
     * - trustStore: provides CA certificates to verify the server
     */
    private SSLContext buildSslContext() throws Exception {
        // keystore type used for .p12 files
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }
        // generate a X509 key manager (standard used in TLS/SSL)
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, keyStorePassword.toCharArray());
        // java native keystore for .jks files
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            trustStore.load(fis, trustStorePassword.toCharArray());
        }
        // X509 trust manager for server certificate chain check
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);
        // with TLS protocol
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }

    @Bean
    public Logger.Level mutualTlsClientLoggerLevel() {return Logger.Level.FULL;}
}
