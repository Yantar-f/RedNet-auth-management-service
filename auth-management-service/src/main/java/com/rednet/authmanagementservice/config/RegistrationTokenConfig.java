package com.rednet.authmanagementservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RegistrationTokenConfig extends TokenConfig {
    public RegistrationTokenConfig(
            @Value("${rednet.app.registration-token.issuer}") String issuer,
            @Value("${rednet.app.registration-token.activation-ms}") long activationMs,
            @Value("${rednet.app.registration-token.expiration-ms}") long expirationMs,
            @Value("${rednet.app.registration-token.allowed-clock-skew-s}") long allowedClockSkew,
            @Value("${rednet.app.registration-token.cookie-name}") String cookieName,
            @Value("${rednet.app.registration-token.cookie-path}") String cookiePath,
            @Value("${rednet.app.registration-token.cookie-expiration-s}") long cookieExpirationS) {
        super(issuer, activationMs, expirationMs, allowedClockSkew, cookieName, cookiePath, cookieExpirationS);
    }

    @Override
    public String getTokenTypeName() {
        return "registration token";
    }
}
