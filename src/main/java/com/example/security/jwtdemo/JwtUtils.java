package com.example.security.jwtdemo;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component // marking as a Spring bean so that it can be autowired where needed.
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwt.expirationMs}")
    private int jwtExpirationMs; // JWT expiration time in milliseconds (1 hour)

    @Value("${spring.app.jwt.secret}")
    private String jwtSecretKey; // coming from application.properties file.

    // Getting JWT from headers
    public String getJwtFromHeaders(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization"); // typically, JWTs are sent in the Authorization header using the Bearer scheme.
        if (authHeader != null && authHeader.startsWith("Bearer ")) { // checks if the Authorization header is present and starts with "Bearer ".
            logger.debug("JWT found in Authorization header: {}", authHeader);
            return authHeader.substring(7); // extracts the actual JWT by removing the "Bearer " prefix.
        }
        return null;
    }

    // Generating JWT from username and roles
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username) // setting the subject of the JWT to the username
                .issuedAt(new Date()) // setting issued at time to current time
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))// setting expiration time 1hr from now
                .signWith(key()) // signing the JWT with the generated key
                .compact(); // builds and serializes the JWT to a compact, URL-safe string
    }

    // Getting username and roles from JWT token
    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key()) // verifying the JWT's signature using the generated signing key.
                .build()// used to create a JwtParser instance with the specified signing key for verifying the JWT's signature.
                .parseSignedClaims(token) // parses the signed JWT token and retrieves the claims.
                .getPayload()// retrieves the payload (claims) from the parsed JWT.
                .getSubject(); // extracts the subject (username) from the claims.
    }

    // Generating signing key
    public Key key() {
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecretKey) // decoding the base64-encoded secret key to get the byte array.
        );
    }

    // Validating JWT token
    public boolean ValidateJwtToken(String token) {
        try {
            System.out.println("Validating token: " + token);
            Jwts.parser()
                    .verifyWith((SecretKey) key()) // verifying the JWT's signature using the generated signing key.
                    .build()
                    .parseSignedClaims(token); // parses the signed JWT token to ensure it's valid.
            return true; // if parsing is successful, the token is valid
        } catch (Exception e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        }
        return false; // if any exception occurs during parsing, the token is invalid
    }
}
