package com.auth.provider.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

  @NotBlank private String issuer;

  @NotNull private @Positive Long expiresInSeconds;

  @NotNull private RSAPublicKey publicKey;

  @NotNull private RSAPrivateKey privateKey;
}
