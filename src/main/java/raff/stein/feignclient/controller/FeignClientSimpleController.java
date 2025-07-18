package raff.stein.feignclient.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import raff.stein.feignclient.service.FeignClientSimpleService;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class FeignClientSimpleController {

    private final FeignClientSimpleService feignClientSimpleService;

    @GetMapping("/basic-auth")
    public ResponseEntity<String> getDataWithBasicAuth() {
        final String responseString = feignClientSimpleService.simpleBasicAuthClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/oauth2")
    public ResponseEntity<String> getDataWithOauth2() {
        final String responseString = feignClientSimpleService.simpleOAuth2ClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/ntlm")
    public ResponseEntity<String> getDataWithNtlm() {
        final String responseString = feignClientSimpleService.simpleNTLMClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/api-key")
    public ResponseEntity<String> getDataWithApiKey() {
        final String responseString = feignClientSimpleService.simpleApiKeyClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/jwt")
    public ResponseEntity<String> getDataWithJwt(@RequestHeader("Authorization") String authHeader) {
        final String responseString = feignClientSimpleService.simpleJwtClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/digest")
    public ResponseEntity<String> getDataWithDigest() {
        final String responseString = feignClientSimpleService.simpleDigestClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/mutual-tls")
    public ResponseEntity<String> getDataWithMutualTls() {
        final String responseString = feignClientSimpleService.simpleMutualTlsClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/hmac")
    public ResponseEntity<String> getDataWithHmac() {
        final String responseString = feignClientSimpleService.simpleHashBasedMessageAuthClientCall();
        return ResponseEntity.ok(responseString);
    }

    @GetMapping("/saml")
    public ResponseEntity<String> getDataWithSaml() {
        final String responseString = feignClientSimpleService.simpleSamlClientCall();
        return ResponseEntity.ok(responseString);
    }

}
