package com.auth.provider.service;

import com.auth.provider.model.TokenResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenGeneratorTest {

  @Mock JwtEncoder encoder;

  @Test
  void shouldGenerateToken() {

    TokenGenerator generator = new TokenGenerator(encoder);
    Instant now = Instant.now();
    Instant expiresAt = now.plusSeconds(3600);

    Jwt jwt =
        new Jwt(
            "token-123",
            now,
            expiresAt,
            Map.of("alg", "none"),
            Map.of("sub", "praveen", "scope", "read"));

    when(encoder.encode(any())).thenReturn(jwt);

    Authentication authentication =
        new UsernamePasswordAuthenticationToken(
            "praveen", "password", List.of(new SimpleGrantedAuthority("read")));

    TokenResponse response = generator.generateToken(authentication);

    assertThat(response.token()).isEqualTo("token-123");
    assertThat(response.type()).isEqualTo("Bearer");
    assertThat(response.scope()).isEqualTo("read");
    assertThat(response.expiresIn()).isBetween(3500L, 3600L);
  }
}
