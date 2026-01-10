package com.example.security.jwtdemo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // declare this class as a Spring bean so that it can be autowired where needed.
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,  // HTTP request object containing client request data.
                                    HttpServletResponse response,  // HTTP response object to send responses back to the client.
                                    FilterChain filterChain) // chain of filters that the request will pass through.
            throws ServletException, IOException {
        logger.debug("Authenticating request: {} {}", request.getMethod(), request.getRequestURI());

        try{
            String jwt = parseJwt(request); // extracting JWT from the request headers.
            if(jwt != null && jwtUtils.validateJwtToken(jwt)) { // validating the extracted JWT.
                String username = jwtUtils.getUsernameFromJwtToken(jwt); // extracting username from the valid JWT.

                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // loading user details using the extracted username.

                UsernamePasswordAuthenticationToken authenticationToken = // extracting user details using the extracted username.
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                // setting the authentication token in the security context.
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                logger.debug("User '{}' authenticated successfully", username);
                logger.debug("roles assigned: {}", userDetails.getAuthorities());
            } else {
                logger.error("No valid JWT token found in request headers");
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        filterChain.doFilter(request, response); // passing the request and response to the next filter in the chain.
    }

    private String parseJwt(HttpServletRequest request) {
        logger.debug("Parsing JWT from request headers");
        return jwtUtils.getJwtFromHeaders(request);
    }
}
