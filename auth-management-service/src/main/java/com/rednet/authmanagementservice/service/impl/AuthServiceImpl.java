package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.config.EnumTokenType;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.impl.InvalidRegistrationActivationCodeException;
import com.rednet.authmanagementservice.exception.impl.InvalidTokenException;
import com.rednet.authmanagementservice.exception.impl.MissingTokenException;
import com.rednet.authmanagementservice.exception.impl.OccupiedValuesException;
import com.rednet.authmanagementservice.exception.impl.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.impl.RegistrationNotFoundException;
import com.rednet.authmanagementservice.payload.request.ChangePasswordRequestMessage;
import com.rednet.authmanagementservice.payload.request.SigninRequestMessage;
import com.rednet.authmanagementservice.payload.request.SignupRequestMessage;
import com.rednet.authmanagementservice.payload.response.SignupResponseMessage;
import com.rednet.authmanagementservice.payload.response.SimpleResponseMessage;
import com.rednet.authmanagementservice.payload.request.VerifyEmailRequestMessage;
import com.rednet.authmanagementservice.payload.response.SigninResponseMessage;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.repository.RefreshTokenRepository;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.util.JwtUtil;
import com.rednet.authmanagementservice.util.SessionPostfixGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final RegistrationRepository registrationRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ActivationCodeGenerator activationCodeGenerator;
    private final SessionPostfixGenerator sessionPostfixGenerator;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final JwtUtil jwtUtil;
    private final String accessTokenCookieName;
    private final String accessTokenCookiePath;
    private final long accessTokenCookieExpirationS;
    private final long accessTokenExpirationMs;
    private final String registrationTokenCookiePath;
    private final String registrationTokenCookieName;
    private final long registrationTokenActivationMs;
    private final long registrationExpirationMs;
    private final long registrationTokenCookieExpirationS;
    private final String refreshTokenCookiePath;
    private final String refreshTokenCookieName;
    private final long refreshTokenExpirationMs;
    private final long refreshTokenCookieExpirationS;

    public AuthServiceImpl(
        AccountRepository accountRepository,
        RegistrationRepository registrationRepository,
        RefreshTokenRepository refreshTokenRepository,
        ActivationCodeGenerator activationCodeGenerator,
        SessionPostfixGenerator sessionPostfixGenerator,
        PasswordEncoder passwordEncoder,
        SessionService sessionService,
        JwtUtil jwtUtil,
        @Value("${rednet.app.access-token-cookie-name}") String accessTokenCookieName,
        @Value("${rednet.app.access-token-cookie-path}") String accessTokenCookiePath,
        @Value("${rednet.app.access-token-cookie-expiration-s}") long accessTokenCookieExpirationS,
        @Value("${rednet.app.access-token-expiration-ms}") long accessTokenExpirationMs,
        @Value("${rednet.app.registration-token-cookie-path}") String registrationTokenCookiePath,
        @Value("${rednet.app.registration-token-cookie-name}") String registrationTokenCookieName,
        @Value("${rednet.app.registration-token-activation-ms}") long registrationTokenActivationMs,
        @Value("${rednet.app.registration-token-expiration-ms}") long registrationExpirationMs,
        @Value("${rednet.app.registration-token-cookie-expiration-s}") long registrationTokenCookieExpirationS,
        @Value("${rednet.app.refresh-token-cookie-path}") String refreshTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-name}") String refreshTokenCookieName,
        @Value("${rednet.app.refresh-token-expiration-ms}") long refreshTokenExpirationMs,
        @Value("${rednet.app.refresh-token-cookie-expiration-s}") long refreshTokenCookieExpirationS
    ) {
        this.accountRepository = accountRepository;
        this.registrationRepository = registrationRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.activationCodeGenerator = activationCodeGenerator;
        this.sessionPostfixGenerator = sessionPostfixGenerator;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.jwtUtil = jwtUtil;
        this.accessTokenCookieName = accessTokenCookieName;
        this.accessTokenCookiePath = accessTokenCookiePath;
        this.accessTokenCookieExpirationS = accessTokenCookieExpirationS;
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.registrationTokenCookiePath = registrationTokenCookiePath;
        this.registrationTokenCookieName = registrationTokenCookieName;
        this.registrationTokenActivationMs = registrationTokenActivationMs;
        this.registrationExpirationMs = registrationExpirationMs;
        this.registrationTokenCookieExpirationS = registrationTokenCookieExpirationS;
        this.refreshTokenCookiePath = refreshTokenCookiePath;
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
        this.refreshTokenCookieExpirationS = refreshTokenCookieExpirationS;
    }


    @Override
    public ResponseEntity<Object> signup(SignupRequestMessage requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.username(), requestMessage.email())
            .orElse(null);

        if (account != null) {
            throw new OccupiedValuesException(new ArrayList<>(){{
                if (requestMessage.username().equals(account.getUsername())) add("Occupied value: username");
                if (requestMessage.email().equals(account.getEmail())) add("Occupied value: email");
            }});
        }

        String activationCode = String.valueOf(activationCodeGenerator.generate());
        String registrationID = UUID.randomUUID().toString();
        String registrationToken = generateRegistrationToken(registrationID);

        registrationRepository.save(registrationID, new Registration(
            activationCode,
            requestMessage.username(),
            passwordEncoder.encode(requestMessage.password()),
            requestMessage.email(),
            requestMessage.secretWord()
        ));

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateRegistrationCookie(registrationToken).toString())
            .body(new SignupResponseMessage(registrationID));
    }

    @Override
    public ResponseEntity<Object> signin(SigninRequestMessage requestMessage) {
        Account account = accountRepository
            .findEagerByUsernameOrEmail(requestMessage.userIdentifier(), requestMessage.userIdentifier())
            .orElseThrow(InvalidAccountDataException::new);

        if (!passwordEncoder.matches(requestMessage.password(), account.getPassword())) {
            throw new InvalidAccountDataException();
        }

        return createSession(account);
    }

    @Override
    public ResponseEntity<Object> signout(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing authentication token");

        Cookie tokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(refreshTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing authentication token"));

        return deleteSession(tokenCookie.getValue());
    }

    @Override
    public ResponseEntity<Object> refreshTokens(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing refresh token");

        Cookie tokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(refreshTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing refresh token"));

        return refreshSession(tokenCookie.getValue());
    }

    @Override
    public ResponseEntity<Object> verifyEmail(VerifyEmailRequestMessage requestMessage) {
        Registration registration = registrationRepository
            .find(requestMessage.registrationID())
            .orElseThrow(() -> new RegistrationNotFoundException(requestMessage.registrationID()));

        if (!registration.getActivationCode().equals(requestMessage.activationCode())) {
            throw new InvalidRegistrationActivationCodeException(requestMessage.activationCode());
        }

        registrationRepository.delete(requestMessage.registrationID());

        Account account = new Account(
            registration.getUsername(),
            registration.getPassword(),
            registration.getEmail(),
            registration.getSecretWord(),
            new HashSet<>(){{add(EnumRoles.ROLE_USER);}}
        );

        accountRepository.save(account);

        return createSession(account);
    }

    @Override
    public ResponseEntity<Object> resendEmailVerification(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new MissingTokenException("Missing registration token");

        Cookie tokenCookie = Arrays.stream(cookies)
            .filter(cookie -> cookie.getName().equals(registrationTokenCookieName))
            .findFirst()
            .orElseThrow(() -> new MissingTokenException("Missing registration token"));
        String registrationID = jwtUtil.getRegistrationTokenParser().parseClaimsJws(tokenCookie.getValue())
            .getBody().getSubject();
        Registration registration = registrationRepository
            .find(registrationID)
            .orElseThrow(() -> new RegistrationNotFoundException(registrationID));
        String newActivationCode = String.valueOf(activationCodeGenerator.generate());
        String newRegistrationToken = generateRegistrationToken(registrationID);

        registration.setActivationCode(newActivationCode);

        registrationRepository.save(registrationID, registration);

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateRegistrationCookie(newRegistrationToken).toString())
            .body(new SimpleResponseMessage("email verification process updated"));
    }

    @Override
    public ResponseEntity<Object> changePassword(ChangePasswordRequestMessage requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.userIdentifier(), requestMessage.userIdentifier())
            .orElseThrow(InvalidAccountDataException::new);

        if (!passwordEncoder.matches(requestMessage.oldPassword(), account.getPassword())) {
            throw new InvalidAccountDataException();
        }

        account.setPassword(passwordEncoder.encode(requestMessage.newPassword()));

        accountRepository.save(account);

        return ResponseEntity.ok().body(new SimpleResponseMessage("password updated"));
    }

    private ResponseCookie generateCleaningCookie(String name, String path) {
        return ResponseCookie.from(name)
            .path(path)
            .maxAge(0)
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

    private ResponseCookie generateRegistrationCookie(String token) {
        return ResponseCookie.from(registrationTokenCookieName, token)
            .path(registrationTokenCookiePath)
            .maxAge(registrationTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }

    private String generateRefreshToken(String userID, String[] roles, String sessionID) {
        return jwtUtil.generateRefreshTokenBuilder()
            .setSubject(String.valueOf(userID))
            .setId(sessionID)
            .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
            .claim("roles", roles)
            .compact();
    }

    private String generateAccessToken(String userID, String[] roles, String sessionID) {
        return jwtUtil.generateAccessTokenBuilder()
            .setSubject(userID)
            .setId(sessionID)
            .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
            .claim("roles",roles)
            .compact();
    }

    private String generateRegistrationToken(String registrationID) {
        return jwtUtil.generateRegistrationTokenBuilder()
            .setSubject(registrationID)
            .setNotBefore(new Date(System.currentTimeMillis() + registrationTokenActivationMs))
            .setExpiration(new Date(System.currentTimeMillis() + registrationExpirationMs))
            .compact();
    }

    private ResponseEntity<Object> createSession(Account account) {
        String userID = String.valueOf(account.getID());
        String sessionID = sessionService.createSession(userID);
        String[] roles = (String[]) account.getRoles().stream().map(Enum::name).toArray();
        String refreshToken = generateRefreshToken(userID, roles, sessionID);

        refreshTokenRepository.save(sessionID, refreshToken);

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                generateAccessTokenCookie(generateAccessToken(userID, roles, sessionID)).toString())
            .header(
                HttpHeaders.SET_COOKIE,
                generateRefreshTokenCookie(refreshToken).toString())
            .body(new SigninResponseMessage(
                userID,
                roles));
    }

    private ResponseEntity<Object> deleteSession(String refreshToken) {
        try {
            String sessionID = jwtUtil.getRefreshTokenParser().parseClaimsJws(refreshToken).getBody().getId();
            sessionService.deleteSession(sessionID);

            return ResponseEntity.ok()
                .header(
                    HttpHeaders.SET_COOKIE,
                    generateCleaningCookie(accessTokenCookieName,accessTokenCookiePath).toString())
                .header(
                    HttpHeaders.SET_COOKIE,
                    generateCleaningCookie(refreshTokenCookieName,refreshTokenCookiePath).toString())
                .body(new SimpleResponseMessage("Successful logout"));
        } catch (
            SignatureException |
            MalformedJwtException |
            ExpiredJwtException |
            UnsupportedJwtException |
            IllegalArgumentException e
        ) {
            throw new InvalidTokenException(EnumTokenType.REFRESH_TOKEN);
        }
    }

    private ResponseEntity<Object> refreshSession(String refreshToken) {
        try {
            Claims claims = jwtUtil.getRefreshTokenParser().parseClaimsJws(refreshToken).getBody();
            String sessionID = claims.getId();

            sessionService.refreshSession(sessionID);

            String newRefreshToken = jwtUtil.generateRefreshTokenBuilder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
                .compact();

            return ResponseEntity.ok()
                .header(
                    HttpHeaders.SET_COOKIE,
                    generateAccessTokenCookie(generateAccessToken(claims.getSubject(), (String[]) claims.get("roles"), sessionID)).toString())
                .header(
                    HttpHeaders.SET_COOKIE,
                    generateRefreshTokenCookie(newRefreshToken).toString())
                .body(new SimpleResponseMessage("successful refresh token pair"));
        } catch (
            SignatureException |
            MalformedJwtException |
            ExpiredJwtException |
            UnsupportedJwtException |
            IllegalArgumentException e
        ) {
            throw new InvalidTokenException(EnumTokenType.REFRESH_TOKEN);
        }
    }
}
