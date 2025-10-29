package com.auth.provider.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.Principal;

@RestController
@RequestMapping("/home")
public class FrontController {

  @GetMapping("/greet")
  public String home(Principal principal) {
    return "Hello, " + principal.getName();
  }

  @PreAuthorize("hasAuthority('SCOPE_read')")
  @GetMapping("/secure")
  public String secure() {
    return "This is secured!";
  }
}
