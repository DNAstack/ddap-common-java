package com.dnastack.ddap.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

    @Bean
    @ConfigurationProperties("ddap.cors.origins")
    public List<String> allowedOrigins() {
        return new ArrayList<>();
    };

    @Profile("!auth")
    @Bean
    public SecurityWebFilterChain securityWebFilterChainNoAuth(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
            .anyExchange().permitAll()
            .and()
            .cors()
            .and()
            .csrf().disable()
            .build();
    }

    @Profile("auth")
    @Bean
    public SecurityWebFilterChain securityWebFilterChainAuth(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
            .pathMatchers("/actuator/info**", "/actuator/health**")
            .permitAll()
            .and()
            .authorizeExchange()
            .anyExchange().authenticated()
            .and()
            .formLogin()
            .and()
            .cors()
            .and()
            .httpBasic().disable()
            .csrf().disable()
            .build();
    }

    @Profile("auth")
    @Bean
    public MapReactiveUserDetailsService userDetailsService(
        @Value("${spring.security.user.name}") String username,
        @Value("${spring.security.user.password}") String password
    ) {
        UserDetails user = User.withDefaultPasswordEncoder()
            .username(username)
            .password(password)
            .roles("USER")
            .build();
        return new MapReactiveUserDetailsService(user);
    }

}
