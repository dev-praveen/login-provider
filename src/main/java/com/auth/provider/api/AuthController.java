package com.auth.provider.api;

import com.auth.provider.service.TokenGenerator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
  private final TokenGenerator tokenService;

  @PostMapping("/token")
  public String token(Authentication authentication) {

    logger.debug("Token requested for user: '{}'", authentication.getName());
    String token = tokenService.generateToken(authentication);
    logger.debug("Token granted: {}", token);
    return token;
  }


}
