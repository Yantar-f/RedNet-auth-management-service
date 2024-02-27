package com.rednet.authmanagementservice.controller;

import com.rednet.authmanagementservice.config.AccessTokenConfig;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RegistrationTokenConfig;
import com.rednet.authmanagementservice.config.TokenConfig;
import com.rednet.authmanagementservice.model.SessionDTO;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerificationData;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.payload.response.SignupResponseBody;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
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
    private final CookieUtil cookieUtil;

    public AuthController(AuthService authService,
                          AccessTokenConfig accessTokenConfig,
                          RegistrationTokenConfig registrationTokenConfig,
                          RefreshTokenConfig refreshTokenConfig,
                          CookieUtil cookieUtil) {
        this.authService = authService;
        this.accessTokenConfig = accessTokenConfig;
        this.registrationTokenConfig = registrationTokenConfig;
        this.refreshTokenConfig = refreshTokenConfig;
        this.cookieUtil = cookieUtil;
    }




    @PostMapping(path = "/signup",
                 consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<SignupResponseBody> signup(@RequestBody @Valid SignupRequestBody requestBody) {
        RegistrationCredentials registrationCredentials = authService.register(requestBody);

        return ResponseEntity.ok()
                .header(SET_COOKIE, createRegistrationCookie(registrationCredentials.registrationToken()))
                .body(new SignupResponseBody(registrationCredentials.registrationID()));
    }

    @PostMapping(path = "/signin",
                 consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<SessionDTO> signin(@RequestBody @Valid SigninRequestBody requestBody) {
        Session session = authService.login(requestBody);

        return ResponseEntity.ok()
                .header(SET_COOKIE, createAccessTokenCookie(session.getAccessToken()))
                .header(SET_COOKIE, createRefreshTokenCookie(session.getRefreshToken()))
                .body(new SessionDTO(session));
    }

    @PostMapping(path = "/signout")
    public ResponseEntity<Void> signout(HttpServletRequest request) {
        String refreshToken = extractRefreshTokenFromRequest(request);

        authService.logout(refreshToken);

        return ResponseEntity.ok()
                .header(SET_COOKIE, createCleaningTokenCookie(accessTokenConfig))
                .header(SET_COOKIE, createCleaningTokenCookie(refreshTokenConfig))
                .build();
    }

    @PostMapping(path = "/refresh-tokens")
    public ResponseEntity<Void> refreshTokens(HttpServletRequest request) {
        String refreshToken = extractRefreshTokenFromRequest(request);
        Session session = authService.refreshSession(refreshToken);

        return ResponseEntity.ok()
                .header(SET_COOKIE, createAccessTokenCookie(session.getAccessToken()))
                .header(SET_COOKIE, createRefreshTokenCookie(session.getRefreshToken()))
                .build();
    }

    @PostMapping(path = "/verify-email",
                 consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<SessionDTO> verifyEmail(@RequestBody @Valid RegistrationVerificationData requestBody) {
        Session session = authService.verifyEmail(requestBody);

        return ResponseEntity.ok()
                .header(SET_COOKIE, createCleaningTokenCookie(registrationTokenConfig))
                .header(SET_COOKIE, createAccessTokenCookie(session.getAccessToken()))
                .header(SET_COOKIE, createRefreshTokenCookie(session.getRefreshToken()))
                .body(new SessionDTO(session));
    }

    @PostMapping(path = "/resend-email-verification")
    public ResponseEntity<Void> resendEmailVerification(HttpServletRequest request) {
        String oldRegistrationToken = extractRegistrationTokenFromRequest(request);
        String newRegistrationToken = authService.resendEmailVerification(oldRegistrationToken);

        return ResponseEntity.ok()
                .header(SET_COOKIE, createRegistrationCookie(newRegistrationToken))
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

    private String createCleaningTokenCookie(TokenConfig config) {
        return cookieUtil.createCleaningCookie(config.getCookieName(), config.getCookiePath()).toString();
    }

    private String createRegistrationCookie(String token) {
        return cookieUtil.createRegistrationTokenCookie(token).toString();
    }

    private String createAccessTokenCookie(String token) {
        return cookieUtil.createAccessTokenCookie(token).toString();
    }

    private String createRefreshTokenCookie(String token) {
        return cookieUtil.createRefreshTokenCookie(token).toString();
    }
}
