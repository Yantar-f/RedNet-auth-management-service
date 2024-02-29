package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.config.AccessTokenConfig;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RegistrationTokenConfig;
import com.rednet.authmanagementservice.config.TokenConfig;
import com.rednet.authmanagementservice.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

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
    public ResponseCookie createAccessTokenCleaningCookie() {
        return createTokenCleaningCookie(accessTokenConfig);
    }

    @Override
    public ResponseCookie createRegistrationTokenCleaningCookie() {
        return createTokenCleaningCookie(registrationTokenConfig);
    }

    @Override
    public ResponseCookie createRefreshTokenCleaningCookie() {
        return createTokenCleaningCookie(refreshTokenConfig);
    }

    @Override
    public Optional<String> extractAccessTokenFromCookies(Cookie[] cookies) {
        return extractTokenFromCookies(cookies, accessTokenConfig);
    }

    @Override
    public Optional<String> extractRegistrationTokenFromCookies(Cookie[] cookies) {
        return extractTokenFromCookies(cookies, registrationTokenConfig);
    }

    @Override
    public Optional<String> extractRefreshTokenFromCookies(Cookie[] cookies) {
        return extractTokenFromCookies(cookies, refreshTokenConfig);
    }

    private Optional<String> extractTokenFromCookies(Cookie[] cookies, TokenConfig tokenConfig) {
        return Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(tokenConfig.getCookieName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    private ResponseCookie createTokenCleaningCookie(TokenConfig config) {
        return createCleaningCookie(config.getCookieName(), config.getCookiePath());
    }

    private ResponseCookie createCleaningCookie(String name, String path) {
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
