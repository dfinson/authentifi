package dev.sanda.authentifi.web.dto;

import lombok.Data;

@Data
public class DirectSignupRequest {
    private String username;
    private String password;
}
