package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.config.ApiTokenConfig;
import com.rednet.authmanagementservice.config.RegistrationTokenConfig;
import com.rednet.authmanagementservice.config.RolesEnum;
import com.rednet.authmanagementservice.config.TokenConfig;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.model.RegistrationTokenClaims;
import com.rednet.authmanagementservice.model.SystemTokenClaims;
import com.rednet.authmanagementservice.util.TokenUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static io.jsonwebtoken.io.Decoders.BASE64;

@Component
public class TokenUtilImpl implements TokenUtil {
    private final ApiTokenConfig apiTokenConfig;
    private final RegistrationTokenConfig registrationTokenConfig;
    private final JwtParser apiTokenParser;
    private final JwtParser registrationTokenParser;

    public TokenUtilImpl(ApiTokenConfig apiTokenConfig, RegistrationTokenConfig registrationTokenConfig) {
        this.apiTokenConfig = apiTokenConfig;
        this.registrationTokenConfig = registrationTokenConfig;
        apiTokenParser = buildTokenParserWith(apiTokenConfig);
        registrationTokenParser = buildTokenParserWith(registrationTokenConfig);
    }

    @Override
    public String generateRegistrationToken(RegistrationTokenClaims claims) {
        return Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(BASE64.decode(registrationTokenConfig.getSecretKey())), HS256)
                .setIssuer(registrationTokenConfig.getIssuer())
                .setExpiration(Date.from(Instant.now().plusMillis(registrationTokenConfig.getExpirationMs())))
                .setSubject(claims.getRegistrationID())
                .setId(claims.getTokenID())
                .compact();
    }

    @Override
    public RegistrationTokenClaims parseRegistrationToken(String token) {
        try {
            Claims claimsMap = extractClaimsMapWith(registrationTokenParser, token);
            String tokenID = extractTokenIDFrom(claimsMap);
            String registrationID = extractRegistrationIDFrom(claimsMap);

            return new RegistrationTokenClaims(tokenID, registrationID);
        } catch (SignatureException |
                 MalformedJwtException |
                 ExpiredJwtException |
                 UnsupportedJwtException |
                 IllegalArgumentException |
                 ClassCastException exception) {
            throw new InvalidTokenException(registrationTokenConfig);
        }
    }

    @Override
    public SystemTokenClaims parseApiToken(String token) {
        try {
            Claims claimsMap = extractClaimsMapWith(apiTokenParser, token);
            String subjectID = extractSubjectIDFrom(claimsMap);
            String sessionID = extractSessionIDFrom(claimsMap);
            String tokenID = extractTokenIDFrom(claimsMap);
            List<RolesEnum> roles = extractRolesFrom(claimsMap);

            return new SystemTokenClaims(subjectID, sessionID, tokenID, roles);
        } catch (SignatureException |
                 MalformedJwtException |
                 ExpiredJwtException |
                 UnsupportedJwtException |
                 IllegalArgumentException |
                 ClassCastException exception) {
            throw new InvalidTokenException(apiTokenConfig);
        }
    }

    private String extractSessionIDFrom(Claims claimsMap) {
        return claimsMap.get("sid", String.class);
    }

    private String extractSubjectIDFrom(Claims claimsMap) {
        return claimsMap.getSubject();
    }

    private List<RolesEnum> extractRolesFrom(Claims claimsMap) {
        List<?> convertedRoles = claimsMap.get("roles", ArrayList.class);

        return convertedRoles.stream()
                .map(String::valueOf)
                .map(RolesEnum::valueOf)
                .toList();
    }

    private String extractRegistrationIDFrom(Claims claimsMap) {
        return extractSubjectIDFrom(claimsMap);
    }

    private String extractTokenIDFrom(Claims claimsMap) {
        return claimsMap.getId();
    }

    private Claims extractClaimsMapWith(JwtParser tokenParser, String token) {
        return tokenParser.parseClaimsJws(token).getBody();
    }

    private JwtParser buildTokenParserWith(TokenConfig config) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(BASE64.decode(config.getSecretKey())))
                .requireIssuer(config.getIssuer())
                .setAllowedClockSkewSeconds(config.getAllowedClockSkew())
                .build();
    }
}
