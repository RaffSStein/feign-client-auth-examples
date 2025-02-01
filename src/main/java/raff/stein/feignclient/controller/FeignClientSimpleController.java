package raff.stein.feignclient.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import raff.stein.feignclient.service.FeignClientSimpleService;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class FeignClientSimpleController {

    private final FeignClientSimpleService feignClientSimpleService;

    @GetMapping("/basic-auth")
    public ResponseEntity<String> getSecureData() {
        final String responseString = feignClientSimpleService.simpleBasicAuthClientCall();
        return ResponseEntity.ok(responseString);
    }

}
