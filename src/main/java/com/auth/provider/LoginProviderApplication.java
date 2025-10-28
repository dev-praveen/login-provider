package com.auth.provider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class LoginProviderApplication {

  public static void main(String[] args) {
    SpringApplication.run(LoginProviderApplication.class, args);
  }
}
