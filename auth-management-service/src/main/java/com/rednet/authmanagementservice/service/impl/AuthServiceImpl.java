package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.exception.OccupiedValuesException;
import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.payload.request.ChangePasswordRequestMessage;
import com.rednet.authmanagementservice.payload.request.SigninRequestMessage;
import com.rednet.authmanagementservice.payload.request.SignupRequestMessage;
import com.rednet.authmanagementservice.payload.response.SignupResponseMessage;
import com.rednet.authmanagementservice.payload.response.SimpleResponseMessage;
import com.rednet.authmanagementservice.payload.request.VerifyEmailRequestMessage;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final RegistrationRepository registrationRepository;
    private final PasswordEncoder passwordEncoder;
    private final String accessTokenCookieName;
    private final JwtUtil jwtUtil;
    private final String accessTokenCookiePath;
    private final String refreshTokenCookiePath;
    private final String refreshTokenCookieName;
    private final ActivationCodeGenerator activationCodeGenerator;
    private final long registrationTokenActivationMs;
    private final long registrationExpirationMs;

    @Autowired
    public AuthServiceImpl(
        AccountRepository accountRepository,
        RegistrationRepository registrationRepository, PasswordEncoder passwordEncoder,
        JwtUtil jwtUtil,
        @Value("${rednet.app.access-token-cookie-name}") String accessTokenCookieName,
        @Value("${rednet.app.access-token-cookie-path}") String accessTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-name}") String refreshTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-path}") String refreshTokenCookieName,
        ActivationCodeGenerator activationCodeGenerator,
        @Value("${rednet.app.registration-token-activation-ms}") long registrationTokenActivationMs,
        @Value("${rednet.app.registration-expiration-ms}") long registrationExpirationMs
    ) {
        this.accountRepository = accountRepository;
        this.registrationRepository = registrationRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenCookieName = accessTokenCookieName;
        this.jwtUtil = jwtUtil;
        this.refreshTokenCookiePath = refreshTokenCookiePath;
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.accessTokenCookiePath = accessTokenCookiePath;
        this.activationCodeGenerator = activationCodeGenerator;
        this.registrationTokenActivationMs = registrationTokenActivationMs;
        this.registrationExpirationMs = registrationExpirationMs;
    }

    @Override
    public ResponseEntity<Object> signup(SignupRequestMessage requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.getUsername(), requestMessage.getEmail())
            .orElse(null);

        if (account != null) {
            throw new OccupiedValuesException(new ArrayList<>(){{
                if (requestMessage.getUsername().equals(account.getUsername())) add("Occupied value: username");
                if (requestMessage.getEmail().equals(account.getEmail())) add("Occupied value: email");
            }});
        }

        int activationCode = activationCodeGenerator.generate();
        String registrationID = UUID.randomUUID().toString();
        String registrationToken = jwtUtil.generateRegistrationTokenBuilder()
            .setSubject(registrationID)
            .setNotBefore(new Date(System.currentTimeMillis() + registrationTokenActivationMs))
            .setExpiration(new Date(System.currentTimeMillis() + registrationExpirationMs))
            .compact();


        registrationRepository.save(registrationID, new Registration(
            String.valueOf(activationCode),
            requestMessage.getUsername(),
            passwordEncoder.encode(requestMessage.getPassword()),
            requestMessage.getEmail(),
            requestMessage.getSecretWord()
        ));

        return ResponseEntity.ok()
            .header(
                HttpHeaders.COOKIE,
                generateRegistrationCookie(registrationToken).toString())
            .body(new SignupResponseMessage(registrationID));
    }

    @Override
    public ResponseEntity<Object> signin(SigninRequestMessage requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.getUserIdentifier(), requestMessage.getUserIdentifier())
            .orElseThrow(InvalidAccountDataException::new);

        if (!passwordEncoder.matches(requestMessage.getPassword(), account.getPassword())) {
            throw new InvalidAccountDataException();
        }



        ///
        /// create refresh token
        ///

        return null;
    }

    @Override
    public ResponseEntity<Object> signout(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing authentication token");

        Cookie tokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(accessTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing authentication token"));

        ///
        /// delete refresh token
        ///

        return ResponseEntity.ok()
            .header(
                HttpHeaders.COOKIE,
                generateCleaningCookie(accessTokenCookieName,accessTokenCookiePath).toString())
            .header(
                HttpHeaders.COOKIE,
                generateCleaningCookie(refreshTokenCookieName,refreshTokenCookiePath).toString())
            .body(new SimpleResponseMessage("Successful logout"));
    }

    @Override
    public ResponseEntity<Object> refreshTokens(HttpServletRequest request) {
        return null;
    }

    @Override
    public ResponseEntity<Object> verifyEmail(VerifyEmailRequestMessage requestMessage) {
        return null;
    }

    @Override
    public ResponseEntity<Object> resendEmailVerification(HttpServletRequest token) {
        return null;
    }

    @Override
    public ResponseEntity<Object> changePassword(ChangePasswordRequestMessage requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.getUserIdentifier(), requestMessage.getUserIdentifier())
            .orElseThrow(InvalidAccountDataException::new);

        if (!passwordEncoder.matches(requestMessage.getOldPassword(), account.getPassword())) {
            throw new InvalidAccountDataException();
        }

        account.setPassword(passwordEncoder.encode(requestMessage.getNewPassword()));

        accountRepository.save(account);

        return ResponseEntity.ok().body(new SimpleResponseMessage("password updated"));
    }

    private ResponseCookie generateCleaningCookie(String name, String path) {
        return ResponseCookie.from(name)
            .path(path)
            .maxAge(0)
            .build();
    }

    private ResponseCookie generateRegistrationCookie(String value) {
        return ResponseCookie.from()
            .value(value)
            .path(path)
            .maxAge(0)
            .build();
    }

}
