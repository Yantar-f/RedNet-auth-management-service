package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.util.JwtUtil;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;

@Component
public class JwtUtilImpl implements JwtUtil {
    private final String accessTokenSecretKey;
    private final String refreshTokenSecretKey;
    private final String registrationTokenSecretKey;
    private final String authTokenIssuer;
    private final JwtParser accessTokenParser;
    private final JwtParser refreshTokenParser;
    private final JwtParser registrationTokenParser;

    public JwtUtilImpl(
        @Value("${rednet.app.access-token-secret-key}") String accessTokenSecretKey,
        @Value("${rednet.app.refresh-token-secret-key}") String refreshTokenSecretKey,
        @Value("${rednet.app.registration-token-secret-key}") String registrationTokenSecretKey,
        @Value("${rednet.app.auth-token-issuer}") String authTokenIssuer
    ) {
        this.accessTokenSecretKey = accessTokenSecretKey;
        this.refreshTokenSecretKey = refreshTokenSecretKey;
        this.registrationTokenSecretKey = registrationTokenSecretKey;
        this.authTokenIssuer = authTokenIssuer;
        this.accessTokenParser = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessTokenSecretKey)))
            .requireIssuer(authTokenIssuer)
            .setAllowedClockSkewSeconds(5)
            .build();
        this.refreshTokenParser = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshTokenSecretKey)))
            .requireIssuer(authTokenIssuer)
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
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessTokenSecretKey)), HS256);
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
            .setIssuer(authTokenIssuer)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationTokenSecretKey)), HS256);
    }

    @Override
    public JwtParser getAccessTokenParser() {
        return accessTokenParser;
    }

    @Override
    public JwtParser getRefreshTokenParser() {
        return refreshTokenParser;
    }

    @Override
    public JwtParser getRegistrationTokenParser() {
        return registrationTokenParser;
    }
}
