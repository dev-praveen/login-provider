package com.auth.provider.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.time.LocalDate;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

  @GetMapping("/status")
  public String getStatus() {
    final LocalDate now = LocalDate.now();
    logger.info(
        "Authentication Service status checked at {} with Thread {}", now, Thread.currentThread());
    return "Authentication Service is running " + now;
  }
}
