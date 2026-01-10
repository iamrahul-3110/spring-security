package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // this annotation enables method-level security, allowing the use of annotations like @PreAuthorize on methods to enforce security constraints.
public class SecurityConfig {

    @Autowired
    DataSource dataSource; // springboot will autoconfigure the datasource bean using the properties defined in application.properties file.

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable); // this line disables CSRF (Cross-Site Request Forgery) protection for the application.
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/h2-console/**").permitAll() // this line allows unrestricted access to the H2 database console.
                .anyRequest().authenticated());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // this line configures the session management policy to be stateless.
//        http.formLogin(Customizer.withDefaults()); // this is form based authentication which have payload of features like login page, logout, remember me, etc.
        // currently this is not stateless application as we are using basic authentication. because this have jsessionid to maintain the session.
        http.httpBasic(Customizer.withDefaults()); // this line configures HTTP Basic authentication for the application which don't have a login page.
        http.headers(headers ->
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)); // this line configures the HTTP headers to allow framing of the H2 console from the same origin.
        return http.build(); // returns the configured SecurityFilterChain
    }

    @Bean
    public UserDetailsService userDetailsService() { // this bean is responsible for retrieving user-related data for authentication and authorization.
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password") // {noop} is used to indicate that no password encoding is applied.
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password("{noop}adminPass") // {noop} is used to indicate that no password encoding is applied.
                .roles("ADMIN")
                .build();

        // using jdbc user details manager to persist users in database instead of in memory.
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;

        // below used in case of in memory user details manager
//        return new InMemoryUserDetailsManager( // InMemoryUserDetailsManager is an implementation of UserDetailsService that stores user details in memory.
//                user1, admin // these are not persist and will be lost when the application restarts.
//        );
    }
}
