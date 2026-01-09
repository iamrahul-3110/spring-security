package com.example.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {
    @GetMapping("/hello")
    public String SayHello() {
        return "Hello, World!";
    }

    @PreAuthorize("hasRole('USER')") // This annotation ensures that only users with the USER role can access this endpoint. check condition before method execution.
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello, User!"; // request is authenticated but if you don't have USER role then access will be denied with 403 forbidden.
    }
    // hasRole & hasAuthority are similar but hasRole automatically adds "ROLE_" prefix to the role name. So hasRole('ADMIN') checks for authority "ROLE_ADMIN".
    @PreAuthorize("hasRole('ADMIN')") // This annotation ensures that only users with the ADMIN role can access this endpoint. check condition before method execution.
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello, Admin!";
    }
}
