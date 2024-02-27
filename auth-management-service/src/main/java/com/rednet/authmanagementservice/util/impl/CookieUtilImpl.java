package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.config.AccessTokenConfig;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RegistrationTokenConfig;
import com.rednet.authmanagementservice.config.TokenConfig;
import com.rednet.authmanagementservice.util.CookieUtil;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtilImpl implements CookieUtil {
    private final AccessTokenConfig accessTokenConfig;
    private final RegistrationTokenConfig registrationTokenConfig;
    private final RefreshTokenConfig refreshTokenConfig;

    public CookieUtilImpl(AccessTokenConfig accessTokenConfig,
                          RegistrationTokenConfig registrationTokenConfig,
                          RefreshTokenConfig refreshTokenConfig) {
        this.accessTokenConfig = accessTokenConfig;
        this.registrationTokenConfig = registrationTokenConfig;
        this.refreshTokenConfig = refreshTokenConfig;
    }

    @Override
    public ResponseCookie createAccessTokenCookie(String accessToken) {
        return createTokenCookie(accessToken, accessTokenConfig);
    }

    @Override
    public ResponseCookie createRegistrationTokenCookie(String registrationToken) {
        return createTokenCookie(registrationToken, registrationTokenConfig);
    }

    @Override
    public ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return createTokenCookie(refreshToken, refreshTokenConfig);
    }

    @Override
    public ResponseCookie createCleaningCookie(String name, String path) {
        return ResponseCookie.from(name)
                .path(path)
                .maxAge(0)
                .build();
    }

    private ResponseCookie createTokenCookie(String token, TokenConfig config) {
        return ResponseCookie.from(config.getCookieName())
                .value(token)
                .path(config.getCookiePath())
                .maxAge(config.getCookieExpirationS())
                .httpOnly(true)
                .build();
    }
}
