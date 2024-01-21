package com.rednet.authmanagementservice.controller;

import com.rednet.authmanagementservice.config.AccessTokenConfig;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RegistrationTokenConfig;
import com.rednet.authmanagementservice.config.TokenConfig;
import com.rednet.authmanagementservice.dto.SessionDTO;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerificationData;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.payload.response.SigninResponseBody;
import com.rednet.authmanagementservice.payload.response.SignupResponseBody;
import com.rednet.authmanagementservice.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.WebUtils;

import java.util.Optional;

import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(produces = APPLICATION_JSON_VALUE)
public class AuthController {
    private final AuthService authService;
    private final AccessTokenConfig accessTokenConfig;
    private final RegistrationTokenConfig registrationTokenConfig;
    private final RefreshTokenConfig refreshTokenConfig;

    public AuthController(AuthService authService,
                          AccessTokenConfig accessTokenConfig,
                          RegistrationTokenConfig registrationTokenConfig,
                          RefreshTokenConfig refreshTokenConfig) {
        this.authService = authService;
        this.accessTokenConfig = accessTokenConfig;
        this.registrationTokenConfig = registrationTokenConfig;
        this.refreshTokenConfig = refreshTokenConfig;
    }




    @PostMapping(path = "/signup",
                 consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<SignupResponseBody> signup(@RequestBody @Valid SignupRequestBody requestBody) {
        RegistrationCredentials registrationCredentials = authService.signup(requestBody);

        return ResponseEntity.ok()
                .header(SET_COOKIE, generateRegistrationCookie(registrationCredentials.registrationToken()))
                .body(new SignupResponseBody(registrationCredentials.registrationID()));
    }

    @PostMapping(path = "/signin",
                 consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<SigninResponseBody> signin(@RequestBody @Valid SigninRequestBody requestBody) {
        SessionDTO session = new SessionDTO(authService.signin(requestBody));

        return ResponseEntity.ok()
                .header(SET_COOKIE, generateAccessTokenCookie(session.getAccessToken()))
                .header(SET_COOKIE, generateRefreshTokenCookie(session.getRefreshToken()))
                .body(new SigninResponseBody(session.getUserID(), session.getRoles()));
    }

    @PostMapping(path = "/signout")
    public ResponseEntity<Void> signout(HttpServletRequest request) {
        String refreshToken = extractRefreshTokenFromRequest(request);

        authService.signout(refreshToken);

        return ResponseEntity.ok()
                .header(SET_COOKIE, generateCleaningTokenCookie(accessTokenConfig))
                .header(SET_COOKIE, generateCleaningTokenCookie(refreshTokenConfig))
                .build();
    }

    @PostMapping(path = "/refresh-tokens")
    public ResponseEntity<Void> refreshTokens(HttpServletRequest request) {
        String refreshToken = extractRefreshTokenFromRequest(request);
        SessionDTO session = new SessionDTO(authService.refreshTokens(refreshToken));

        return ResponseEntity.ok()
            .header(SET_COOKIE, generateAccessTokenCookie(session.getAccessToken()))
            .header(SET_COOKIE, generateRefreshTokenCookie(session.getRefreshToken()))
            .build();
    }

    @PostMapping(path = "/verify-email",
                 consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<SigninResponseBody> verifyEmail(
            @RequestBody @Valid RegistrationVerificationData requestBody) {
        SessionDTO session = new SessionDTO(authService.verifyEmail(requestBody));

        return ResponseEntity.ok()
            .header(SET_COOKIE, generateCleaningTokenCookie(registrationTokenConfig))
            .header(SET_COOKIE, generateAccessTokenCookie(session.getAccessToken()))
            .header(SET_COOKIE, generateRefreshTokenCookie(session.getRefreshToken()))
            .body(new SigninResponseBody(session.getUserID(), session.getRoles()));
    }

    @PostMapping(path = "/resend-email-verification")
    public ResponseEntity<Void> resendEmailVerification(HttpServletRequest request) {
        String oldRegistrationToken = extractRegistrationTokenFromRequest(request);
        String newRegistrationToken = authService.resendEmailVerification(oldRegistrationToken);

        return ResponseEntity.ok()
            .header(SET_COOKIE, generateRegistrationCookie(newRegistrationToken))
            .build();
    }




    private String extractRegistrationTokenFromRequest(HttpServletRequest request) {
        return extractTokenFromRequest(request, registrationTokenConfig);
    }

    private String extractRefreshTokenFromRequest(HttpServletRequest request) {
        return extractTokenFromRequest(request, refreshTokenConfig);
    }

    private String extractTokenFromRequest(HttpServletRequest request, TokenConfig tokenConfig) {
        return Optional
                .ofNullable(WebUtils.getCookie(request, tokenConfig.getCookieName()))
                .map(Cookie::getValue)
                .orElseThrow(() -> new MissingTokenException(tokenConfig));
    }

    private String generateCleaningTokenCookie(TokenConfig config) {
        return generateCleaningCookie(config.getCookieName(), config.getCookiePath());
    }

    private String generateCleaningCookie(String name, String path) {
        return ResponseCookie.from(name)
                .path(path)
                .maxAge(0)
                .build()
                .toString();
    }

    private String generateRegistrationCookie(String token) {
        return createTokenCookie(token, registrationTokenConfig);
    }

    private String generateAccessTokenCookie(String token) {
        return createTokenCookie(token, accessTokenConfig);
    }

    private String generateRefreshTokenCookie(String token) {
        return createTokenCookie(token, refreshTokenConfig);
    }

    private String createTokenCookie(String token, TokenConfig config) {
        return ResponseCookie.from(config.getCookieName())
                .value(token)
                .path(config.getCookiePath())
                .maxAge(config.getCookieExpirationS())
                .httpOnly(true)
                .build()
                .toString();
    }
}
