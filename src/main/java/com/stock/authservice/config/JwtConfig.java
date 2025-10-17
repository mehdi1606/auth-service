package com.stock.authservice.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtConfig {

    private String secret;
    private long accessTokenExpiration;  // milliseconds
    private long refreshTokenExpiration; // milliseconds
    private long mfaTempTokenExpiration; // milliseconds
    private String issuer;
}
