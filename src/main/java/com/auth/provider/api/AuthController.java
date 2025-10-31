package com.auth.provider.api;

import com.auth.provider.model.TokenRequest;
import com.auth.provider.model.TokenResponse;
import com.auth.provider.service.TokenGenerator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
  private final TokenGenerator tokenService;
  private final AuthenticationManager authenticationManager;

  @PostMapping("/token")
  public TokenResponse token(@RequestBody TokenRequest tokenRequest) {

    logger.info("Token requested for user: '{}'", tokenRequest.userName());
    UsernamePasswordAuthenticationToken authRequest =
        new UsernamePasswordAuthenticationToken(tokenRequest.userName(), tokenRequest.password());
    Authentication authentication = authenticationManager.authenticate(authRequest);
    return tokenService.generateToken(authentication);
  }
}
