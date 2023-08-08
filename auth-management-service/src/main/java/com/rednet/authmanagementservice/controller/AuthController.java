package com.rednet.authmanagementservice.controller;

import com.rednet.authmanagementservice.payload.ChangePasswordRequestMessage;
import com.rednet.authmanagementservice.payload.SigninRequestMessage;
import com.rednet.authmanagementservice.payload.SignupRequestMessage;
import com.rednet.authmanagementservice.payload.VerifyEmailRequestMessage;
import com.rednet.authmanagementservice.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {
    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(
        path = "/signup",
        consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> signup(@RequestBody @Valid SignupRequestMessage requestMessage) {
        return authService.signup(requestMessage);
    }

    @PostMapping(
        path = "/signin",
        consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> signin(@RequestBody @Valid SigninRequestMessage requestMessage) {
        return authService.signin(requestMessage);
    }

    @PostMapping(
        path = "/signout",
        consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> signout(HttpServletRequest request) {
        return authService.signout(request);
    }

    @PostMapping(path = "/refresh-tokens")
    public ResponseEntity<Object> refreshTokens(HttpServletRequest request) {
        return authService.refreshTokens(request);
    }

    @PostMapping(
        path = "/verify-email",
        consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> verifyEmail(@RequestBody VerifyEmailRequestMessage requestMessage) {
        return authService.verifyEmail(requestMessage);
    }

    @PostMapping(path = "/resend-email-verification")
    public ResponseEntity<Object> resendEmailVerification(HttpServletRequest request) {
        return authService.resendEmailVerification(request);
    }

    @PostMapping(
        path = "/change-password",
        consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> changePassword(@RequestBody @Valid ChangePasswordRequestMessage requestMessage) {
        return authService.changePassword(requestMessage);
    }
}
