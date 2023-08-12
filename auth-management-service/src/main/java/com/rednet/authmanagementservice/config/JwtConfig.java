package com.rednet.authmanagementservice.config;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class JwtConfig {

    private final String accessTokenSecretKey;
    private final String refreshTokenSecretKey;
    private final String registrationRefreshTokenSecretKey;
    private final String authTokenIssuer;

    public JwtConfig(
        @Value("${rednet.app.access-token-secret-key}") String accessTokenSecretKey,
        @Value("${rednet.app.refresh-token-secret-key}") String refreshTokenSecretKey,
        @Value("${rednet.app.registration-refresh-token-secret-key}") String registrationRefreshTokenSecretKey,
        @Value("${rednet.app.password-encoder-strength}") String authTokenIssuer
    ) {
        this.accessTokenSecretKey = accessTokenSecretKey;
        this.refreshTokenSecretKey = refreshTokenSecretKey;
        this.registrationRefreshTokenSecretKey = registrationRefreshTokenSecretKey;
        this.authTokenIssuer = authTokenIssuer;
    }

    @Bean
    @Qualifier("accessTokenParser")
    public JwtParser accessTokenParser() {
        return  Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessTokenSecretKey)))
            .requireIssuer(authTokenIssuer)
            .setAllowedClockSkewSeconds(5)
            .build();
    }

    @Bean
    @Qualifier("refreshTokenParser")
    public JwtParser refreshTokenParser() {
        return Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshTokenSecretKey)))
            .requireIssuer(authTokenIssuer)
            .setAllowedClockSkewSeconds(5)
            .build();
    }

    @Bean
    @Qualifier("registrationTokenParser")
    public JwtParser registrationTokenParser() {
        return Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationRefreshTokenSecretKey)))
            .requireIssuer(authTokenIssuer)
            .setAllowedClockSkewSeconds(5)
            .build();
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    @Qualifier("accessTokenBuilder")
    public JwtBuilder accessTokenBuilder() {
        return Jwts.builder()
            .setIssuer(authTokenIssuer)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessTokenSecretKey)), SignatureAlgorithm.HS256);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    @Qualifier("refreshTokenBuilder")
    public JwtBuilder refreshTokenBuilder() {
        return Jwts.builder()
            .setIssuer(authTokenIssuer)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshTokenSecretKey)), SignatureAlgorithm.HS256);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    @Qualifier("registrationTokenBuilder")
    public JwtBuilder registrationTokenBuilder() {
        return Jwts.builder()
            .setIssuer(authTokenIssuer)
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(registrationRefreshTokenSecretKey)), SignatureAlgorithm.HS256);
    }
}
