package com.fullcycle.subscription.infrastructure.configuration;

import com.fullcycle.subscription.infrastructure.authentication.principal.KeycloakJwtConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
@Profile("!development")
public class SecurityConfig {

    private final KeycloakJwtConverter jwtConverter;
    private final Environment environment;

    public SecurityConfig(KeycloakJwtConverter jwtConverter, Environment environment) {
        this.jwtConverter = jwtConverter;
        this.environment = environment;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        final var isSandbox = environment.matchesProfiles("sandbox");
        return http
                .csrf(csrf -> {
                    csrf.disable();
                })
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/accounts/sign-up").permitAll();
                    if (isSandbox) {
                        authorize.requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll();
                    }
                    authorize.anyRequest().authenticated();
                })
                .oauth2ResourceServer(oauth -> {
                    oauth.jwt(j -> j.jwtAuthenticationConverter(jwtConverter));
                })
                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .headers(headers -> {
                    headers.frameOptions(opt -> opt.sameOrigin());
                })
                .build();
    }
}