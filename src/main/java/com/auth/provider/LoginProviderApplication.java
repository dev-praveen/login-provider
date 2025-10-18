package com.auth.provider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class LoginProviderApplication {

  public static void main(String[] args) {
    SpringApplication.run(LoginProviderApplication.class, args);
  }

  @RequestMapping("/hello")
  public String hello() {
    return "hello world " + Thread.currentThread().getName();
  }
}
