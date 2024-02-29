package com.rednet.authmanagementservice.util;

import jakarta.servlet.http.Cookie;
import org.springframework.http.ResponseCookie;

import java.util.Optional;

public interface CookieUtil {
    ResponseCookie createAccessTokenCookie          (String accessToken);
    ResponseCookie createRegistrationTokenCookie    (String registrationToken);
    ResponseCookie createRefreshTokenCookie         (String refreshToken);

    ResponseCookie createAccessTokenCleaningCookie();
    ResponseCookie createRegistrationTokenCleaningCookie();
    ResponseCookie createRefreshTokenCleaningCookie();

    Optional<String> extractAccessTokenFromCookies        (Cookie[] cookies);
    Optional<String> extractRegistrationTokenFromCookies  (Cookie[] cookies);
    Optional<String> extractRefreshTokenFromCookies       (Cookie[] cookies);
}
