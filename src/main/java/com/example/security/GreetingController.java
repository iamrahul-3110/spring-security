package com.example.security;

import com.example.security.jwtdemo.JwtUtils;
import com.example.security.jwtdemo.LoginRequest;
import com.example.security.jwtdemo.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class GreetingController {

    @Autowired
    private AuthenticationManager authenticationManager; // need to expose somewhere check Security config

    @Autowired
    private JwtUtils jwtUtils;

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

    @PostMapping("/signing")
    public ResponseEntity<?> authenticateuser(@RequestBody LoginRequest loginRequest) { // send a request
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate( // get the authentication object
              new UsernamePasswordAuthenticationToken(
                      loginRequest.getUsername(),
                      loginRequest.getPassword()
              )
            );
        } catch (AuthenticationException e) { // in case no object catch the exception
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad Credentials");
            map.put("status", false);
            return  new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        assert userDetails != null;
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse loginResponse = new LoginResponse(userDetails.getUsername(), jwtToken, roles);
        return ResponseEntity.ok(loginResponse);
    }
}
