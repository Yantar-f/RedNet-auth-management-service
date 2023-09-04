package com.rednet.authmanagementservice.controller;

import com.rednet.authmanagementservice.dto.SessionDTO;
import com.rednet.authmanagementservice.exception.impl.MissingTokenException;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerifications;
import com.rednet.authmanagementservice.model.ChangePasswordCredentials;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.payload.response.SigninResponseBody;
import com.rednet.authmanagementservice.payload.response.SignupResponseBody;
import com.rednet.authmanagementservice.payload.response.SimpleResponseBody;
import com.rednet.authmanagementservice.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(produces = APPLICATION_JSON_VALUE)
public class AuthController {
    private final AuthService authService;
    private final String accessTokenCookieName;
    private final String accessTokenCookiePath;
    private final long accessTokenCookieExpirationS;
    private final String registrationTokenCookiePath;
    private final String registrationTokenCookieName;
    private final long registrationTokenCookieExpirationS;
    private final String refreshTokenCookiePath;
    private final String refreshTokenCookieName;
    private final long refreshTokenCookieExpirationS;


    public AuthController(
        AuthService authService,
        @Value("${rednet.app.access-token-cookie-name}") String accessTokenCookieName,
        @Value("${rednet.app.access-token-cookie-path}") String accessTokenCookiePath,
        @Value("${rednet.app.access-token-cookie-expiration-s}") long accessTokenCookieExpirationS,
        @Value("${rednet.app.registration-token-cookie-path}") String registrationTokenCookiePath,
        @Value("${rednet.app.registration-token-cookie-name}") String registrationTokenCookieName,
        @Value("${rednet.app.registration-token-cookie-expiration-s}") long registrationTokenCookieExpirationS,
        @Value("${rednet.app.refresh-token-cookie-path}") String refreshTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-name}") String refreshTokenCookieName,
        @Value("${rednet.app.refresh-token-cookie-expiration-s}") long refreshTokenCookieExpirationS

    ) {
        this.authService = authService;
        this.accessTokenCookieName = accessTokenCookieName;
        this.accessTokenCookiePath = accessTokenCookiePath;
        this.accessTokenCookieExpirationS = accessTokenCookieExpirationS;
        this.registrationTokenCookiePath = registrationTokenCookiePath;
        this.registrationTokenCookieName = registrationTokenCookieName;
        this.registrationTokenCookieExpirationS = registrationTokenCookieExpirationS;
        this.refreshTokenCookiePath = refreshTokenCookiePath;
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.refreshTokenCookieExpirationS = refreshTokenCookieExpirationS;
    }

    @PostMapping(
        path = "/signup",
        consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> signup(@RequestBody @Valid SignupRequestBody requestBody) {
        RegistrationCredentials reg = authService.signup(requestBody);
        return ResponseEntity.ok()
                .header(
                    HttpHeaders.SET_COOKIE,
                    generateRegistrationCookie(reg.registrationToken()).toString())
                .body(new SignupResponseBody(reg.registrationID()));
    }

    @PostMapping(
        path = "/signin",
        consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> signin(@RequestBody @Valid SigninRequestBody requestBody) {
        SessionDTO session = authService.signin(requestBody);
        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateAccessTokenCookie(session.getAccessToken()).toString())
            .header(
                HttpHeaders.SET_COOKIE,
                generateRefreshTokenCookie(session.getRefreshToken()).toString())
            .body(new SigninResponseBody(session.getUserID(), session.getRoles()));
    }

    @PostMapping(path = "/signout")
    public ResponseEntity<Object> signout(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing authentication token");

        Cookie refreshTokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(refreshTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing authentication token"));

        authService.signout(refreshTokenCookie.getValue());

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateCleaningCookie(accessTokenCookieName,accessTokenCookiePath).toString())
            .header(
                HttpHeaders.SET_COOKIE,
                generateCleaningCookie(refreshTokenCookieName,refreshTokenCookiePath).toString())
            .body(new SimpleResponseBody("Successful logout"));
    }

    @PostMapping(path = "/refresh-tokens")
    public ResponseEntity<Object> refreshTokens(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing refresh token");

        Cookie refreshTokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(refreshTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing refresh token"));

        SessionDTO session = authService.refreshTokens(refreshTokenCookie.getValue());

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateAccessTokenCookie(session.getAccessToken()).toString())
            .header(
                HttpHeaders.SET_COOKIE,
                generateRefreshTokenCookie(session.getRefreshToken()).toString())
            .body(new SimpleResponseBody("successful refresh token pair"));
    }

    @PostMapping(
        path = "/verify-email",
        consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> verifyEmail(@RequestBody @Valid RegistrationVerifications requestBody) {
        SessionDTO session = authService.verifyEmail(requestBody);
        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateAccessTokenCookie(session.getAccessToken()).toString())
            .header(
                HttpHeaders.SET_COOKIE,
                generateRefreshTokenCookie(session.getRefreshToken()).toString())
            .body(new SigninResponseBody(session.getUserID(), session.getRoles()));
    }

    @PostMapping(path = "/resend-email-verification")
    public ResponseEntity<Object> resendEmailVerification(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing registration token");

        Cookie registrationTokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(registrationTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing registration token"));

        String newRegistrationToken = authService.resendEmailVerification(registrationTokenCookie.getValue());

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateRegistrationCookie(newRegistrationToken).toString())
            .body(new SimpleResponseBody("email verification process updated"));
    }

    @PostMapping(
        path = "/change-password",
        consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> changePassword(@RequestBody @Valid ChangePasswordCredentials requestBody) {
        authService.changePassword(requestBody);
        return ResponseEntity.ok().body(new SimpleResponseBody("password updated"));
    }

    private ResponseCookie generateCleaningCookie(String name, String path) {
        return ResponseCookie.from(name)
            .path(path)
            .maxAge(0)
            .build();
    }

    private ResponseCookie generateRegistrationCookie(String token) {
        return ResponseCookie.from(registrationTokenCookieName, token)
            .path(registrationTokenCookiePath)
            .maxAge(registrationTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }

    private ResponseCookie generateAccessTokenCookie(String token) {
        return ResponseCookie.from(accessTokenCookieName, token)
            .path(accessTokenCookiePath)
            .maxAge(accessTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }

    private ResponseCookie generateRefreshTokenCookie(String token) {
        return ResponseCookie.from(refreshTokenCookieName, token)
            .path(refreshTokenCookiePath)
            .maxAge(refreshTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }
}
