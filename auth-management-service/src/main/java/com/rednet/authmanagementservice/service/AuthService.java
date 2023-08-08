package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.payload.ChangePasswordRequestMessage;
import com.rednet.authmanagementservice.payload.SigninRequestMessage;
import com.rednet.authmanagementservice.payload.SignupRequestMessage;
import com.rednet.authmanagementservice.payload.VerifyEmailRequestMessage;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<Object> signup(SignupRequestMessage requestMessage);

    ResponseEntity<Object> signin(SigninRequestMessage requestMessage);

    ResponseEntity<Object> signout(HttpServletRequest request);

    ResponseEntity<Object> refreshTokens(HttpServletRequest request);

    ResponseEntity<Object> verifyEmail(VerifyEmailRequestMessage requestMessage);

    ResponseEntity<Object> resendEmailVerification(HttpServletRequest token);

    ResponseEntity<Object> changePassword(ChangePasswordRequestMessage requestMessage);
}
