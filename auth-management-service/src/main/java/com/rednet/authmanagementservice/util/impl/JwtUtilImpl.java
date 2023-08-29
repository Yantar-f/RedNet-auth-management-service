package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.util.JwtUtil;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;

@Component
public class JwtUtilImpl implements JwtUtil {
    private final String apiTokenSecretKey;
    private final String refreshTokenSecretKey;
    private final String registrationTokenSecretKey;
    private final String authTokenIssuer;
    private final JwtParser apiTokenParser;
    private final JwtParser registrationTokenParser;
    private final long registrationTokenActivationMs;
    private final long registrationExpirationMs;

    public JwtUtilImpl(
        @Value("${rednet.app.api-token-secret-key}") String apiTokenSecretKey,
        @Value("${rednet.app.refresh-token-secret-key}") String refreshTokenSecretKey,
        @Value("${rednet.app.registration-token-secret-key}") String registrationTokenSecretKey,
        @Value("${rednet.app.auth-token-issuer}") String authTokenIssuer,
        @Value("${rednet.app.api-token-issuer}") String apiTokenIssuer,
        @Value("${rednet.app.registration-token-activation-ms}") long registrationTokenActivationMs,
        @Value("${rednet.app.registration-token-expiration-ms}") long registrationExpirationMs
    ) {
        this.apiTokenSecretKey = apiTokenSecretKey;
        this.refreshTokenSecretKey = refreshTokenSecretKey;
        this.registrationTokenSecretKey = registrationTokenSecretKey;
        this.authTokenIssuer = authTokenIssuer;
        this.registrationTokenActivationMs = registrationTokenActivationMs;
        this.registrationExpirationMs = registrationExpirationMs;
        this.apiTokenParser = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(apiTokenSecretKey)))
            .requireIssuer(apiTokenIssuer)
            .setAllowedClockSkewSeconds(5)
            .build();
        this.registrationTokenParser = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationTokenSecretKey)))
            .requireIssuer(authTokenIssuer)
            .setAllowedClockSkewSeconds(5)
            .build();
    }

    @Override
    public JwtBuilder generateAccessTokenBuilder() {
        return Jwts.builder()
            .setIssuer(authTokenIssuer)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(apiTokenSecretKey)), HS256);
    }

    @Override
    public JwtBuilder generateRefreshTokenBuilder() {
        return Jwts.builder()
            .setIssuer(authTokenIssuer)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshTokenSecretKey)), HS256);
    }

    @Override
    public JwtBuilder generateRegistrationTokenBuilder() {
        return Jwts.builder()
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationTokenSecretKey)), HS256)
            .setIssuer(authTokenIssuer)
            .setNotBefore(new Date(System.currentTimeMillis() + registrationTokenActivationMs))
            .setExpiration(new Date(System.currentTimeMillis() + registrationExpirationMs));
    }

    @Override
    public JwtParser getRegistrationTokenParser() {
        return registrationTokenParser;
    }

    @Override
    public JwtParser getApiTokenParser() {
        return apiTokenParser;
    }
}
