package dev.sanda.authentifi.web.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredPingController {
    @GetMapping("/auth-secured/ping")
    public String ping(){
        return "pong";
    }
}
