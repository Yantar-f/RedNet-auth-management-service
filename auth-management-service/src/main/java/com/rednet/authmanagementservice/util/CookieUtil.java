package com.rednet.authmanagementservice.util;

import org.springframework.http.ResponseCookie;

public interface CookieUtil {
    ResponseCookie createAccessTokenCookie(String accessToken);
    ResponseCookie createRegistrationTokenCookie(String registrationToken);
    ResponseCookie createRefreshTokenCookie(String refreshToken);
    ResponseCookie createCleaningCookie(String name, String path);
}
