package com.example.security;

import com.example.security.jwtdemo.JwtAuthEntryPoint;
import com.example.security.jwtdemo.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;
import javax.xml.crypto.Data;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
// this annotation enables method-level security, allowing the use of annotations like @PreAuthorize on methods to enforce security constraints.
public class SecurityConfig {

    @Autowired
    DataSource dataSource; // springboot will autoconfigure the datasource bean using the properties defined in application.properties file.

    @Autowired
    private JwtAuthEntryPoint unauthorizeHandler;

    @Bean
    public JwtAuthFilter authenticationJwtTokenFilter() {
        return new JwtAuthFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable); // this line disables CSRF (Cross-Site Request Forgery) protection for the application.

        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/h2-console/**").permitAll() // this line allows unrestricted access to the H2 database console.
                        .requestMatchers("/signing").permitAll() // allowing for any request for signing
                        .anyRequest().authenticated());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // this line configures the session management policy to be stateless.
//        http.formLogin(Customizer.withDefaults()); // this is form based authentication which have payload of features like login page, logout, remember me, etc.
        // currently this is not stateless application as we are using basic authentication. because this have jsessionid to maintain the session.

//        http.httpBasic(Customizer.withDefaults()); // this line configures HTTP Basic authentication for the application which don't have a login page.
        http.exceptionHandling(exception -> exception
                .authenticationEntryPoint(unauthorizeHandler) // using our own handler if any sort of unauthorized access
        );

        http.headers(headers ->
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)); // this line configures the HTTP headers to allow framing of the H2 console from the same origin.

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class); // choosing my own filter before other filter is running

        return http.build(); // returns the configured SecurityFilterChain
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) { // this bean is responsible for retrieving user-related data for authentication and authorization.

        return new JdbcUserDetailsManager(dataSource);

        // below used in case of in memory user details manager
//        return new InMemoryUserDetailsManager( // InMemoryUserDetailsManager is an implementation of UserDetailsService that stores user details in memory.
//                user1, admin // these are not persist and will be lost when the application restarts.
//        );
    }

    // user creation part separated from above ---
    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user")
                    .password(passwordEncoder().encode("password")) // {noop} is used to indicate that no password encoding is applied.
                    .roles("USER")
                    .build();
            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder().encode("adminPass")) // currently passwords are in plain text which is not recommended for production use. we use password encoders for that.
                    .roles("ADMIN")
                    .build();

            // using jdbc user details manager to persist users in database instead of in memory.
            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // automatically provide salt and use strong hashing algorithm to encode the password.
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
