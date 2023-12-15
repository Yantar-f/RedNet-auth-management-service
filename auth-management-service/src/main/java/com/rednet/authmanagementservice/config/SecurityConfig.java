package com.rednet.authmanagementservice.config;

import com.rednet.authmanagementservice.entity.Role;
import com.rednet.authmanagementservice.filter.ApiTokenFilter;
import com.rednet.authmanagementservice.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final int passwordEncoderStrength;
    private final ApiTokenFilter apiTokenFilter;
    private final AccessDeniedHandler accessDeniedHandler;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    public SecurityConfig(
        @Value("${rednet.app.password-encoder-strength}") int passwordEncoderStrength,
        ApiTokenFilter apiTokenFilter,
        AccessDeniedHandler accessDeniedHandler,
        AuthenticationEntryPoint authenticationEntryPoint,
        RoleRepository roleRepository
    ) {
        this.passwordEncoderStrength = passwordEncoderStrength;
        this.apiTokenFilter = apiTokenFilter;
        this.accessDeniedHandler = accessDeniedHandler;
        this.authenticationEntryPoint = authenticationEntryPoint;

        roleRepository.saveAll(Arrays.stream(EnumRoles.values())
            .filter(enumRole -> !roleRepository.existsByDesignation(enumRole.name()))
            .map(Role::new).toList());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(passwordEncoderStrength);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .csrf(CsrfConfigurer::disable)
            .cors(CorsConfigurer::disable)
            .httpBasic(HttpBasicConfigurer::disable)
            .formLogin(FormLoginConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .exceptionHandling(exHandle -> exHandle
                .accessDeniedHandler(accessDeniedHandler)
                .authenticationEntryPoint(authenticationEntryPoint))
            .addFilterBefore(apiTokenFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
