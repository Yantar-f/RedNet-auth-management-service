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
    private final String registrationTokenSecretKey;
    private final String registrationTokenIssuer;
    private final JwtParser apiTokenParser;
    private final JwtParser registrationTokenParser;
    private final long registrationTokenActivationMs;
    private final long registrationExpirationMs;

    public JwtUtilImpl(
        @Value("${rednet.app.security.api-token.secret-key}") String apiTokenSecretKey,
        @Value("${rednet.app.security.api-token.issuer}") String apiTokenIssuer,
        @Value("${rednet.app.security.api-token.allowed-clock-skew-s}") long apiTokenAllowedClockSkewS,
        @Value("${rednet.app.registration-token.secret-key}") String registrationTokenSecretKey,
        @Value("${rednet.app.registration-token.issuer}") String registrationTokenIssuer,
        @Value("${rednet.app.registration-token.activation-ms}") long registrationTokenActivationMs,
        @Value("${rednet.app.registration-token.expiration-ms}") long registrationExpirationMs,
        @Value("${rednet.app.registration-token.allowed-clock-skew-s}") long registrationTokenAllowedClockSkewS
    ) {
        this.registrationTokenSecretKey = registrationTokenSecretKey;
        this.registrationTokenIssuer = registrationTokenIssuer;
        this.registrationTokenActivationMs = registrationTokenActivationMs;
        this.registrationExpirationMs = registrationExpirationMs;

        this.apiTokenParser = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(apiTokenSecretKey)))
            .requireIssuer(apiTokenIssuer)
            .setAllowedClockSkewSeconds(apiTokenAllowedClockSkewS)
            .build();

        this.registrationTokenParser = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationTokenSecretKey)))
            .requireIssuer(registrationTokenIssuer)
            .setAllowedClockSkewSeconds(registrationTokenAllowedClockSkewS)
            .build();
    }

    @Override
    public JwtBuilder generateRegistrationTokenBuilder() {
        return Jwts.builder()
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationTokenSecretKey)), HS256)
            .setIssuer(registrationTokenIssuer)
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
