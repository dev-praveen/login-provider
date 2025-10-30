package com.auth.provider.service;

import com.auth.provider.model.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TokenGenerator {

  private final JwtEncoder encoder;

  public TokenResponse generateToken(Authentication authentication) {

    Instant now = Instant.now();
    Instant expiresAt = now.plus(1, ChronoUnit.HOURS);

    String scope =
        authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(" "));
    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer("self")
            .issuedAt(now)
            .expiresAt(expiresAt)
            .subject(authentication.getName())
            .claim("scope", scope)
            .build();

    String tokenValue = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    long expiresIn = ChronoUnit.SECONDS.between(now, expiresAt);
    return new TokenResponse(tokenValue, expiresIn, "Bearer", scope);
  }
}
