package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.InvalidRegistrationActivationCodeException;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.exception.OccupiedValuesException;
import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.RegistrationNotFoundException;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final ActivationCodeGenerator activationCodeGenerator;
    private final RegistrationRepository registrationRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final String accessTokenCookieName;
    private final String accessTokenCookiePath;
    private final long accessTokenCookieExpirationS;
    private final long accessTokenExpirationMs;
    private final String registrationTokenCookiePath;
    private final String registrationTokenCookieName;
    private final String refreshTokenCookiePath;
    private final String refreshTokenCookieName;
    private final long registrationTokenActivationMs;
    private final long registrationTokenCookieExpirationS;
    private final long registrationExpirationMs;
    private final long refreshTokenExpirationMs;
    private final long refreshTokenCookieExpirationS;
    private final SessionPostfixGenerator sessionPostfixGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionService sessionService;


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

        try {
            String sessionID = jwtUtil.getRefreshTokenParser().parseClaimsJws(tokenCookie.getValue()).getBody().getId();
            sessionService.deleteSession(sessionID);
        } catch (
            SignatureException |
            MalformedJwtException |
            ExpiredJwtException |
            UnsupportedJwtException |
            IllegalArgumentException e
        ) {
            throw new InvalidTokenException();
        }

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
        Registration registration = registrationRepository
            .find(requestMessage.getRegistrationID())
            .orElseThrow(() -> new RegistrationNotFoundException(requestMessage.getRegistrationID()));

        if (!registration.getActivationCode().equals(requestMessage.getActivationCode())) {
            throw new InvalidRegistrationActivationCodeException(requestMessage.getActivationCode());
        }

        registrationRepository.delete(requestMessage.getRegistrationID());

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

    private ResponseCookie generateAccessTokenCookie(String value) {
        return ResponseCookie.from(accessTokenCookieName, value)
            .path(accessTokenCookiePath)
            .maxAge(accessTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }

    private ResponseCookie generateRefreshTokenCookie(String value) {
        return ResponseCookie.from(refreshTokenCookieName, value)
            .path(refreshTokenCookiePath)
            .maxAge(refreshTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }

    private ResponseCookie generateRegistrationCookie(String value) {
        return ResponseCookie.from(registrationTokenCookieName, value)
            .path(registrationTokenCookiePath)
            .maxAge(registrationTokenCookieExpirationS)
            .httpOnly(true)
            .build();
    }

    private String generateRefreshToken(Account account, String sessionID) {
        return jwtUtil.generateRefreshTokenBuilder()
            .setSubject(String.valueOf(account.getID()))
            .setId(sessionID)
            .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
            .claim("roles", account.getRoles().toArray())
            .compact();
    }

    private String generateAccessToken(Account account, String sessionID) {
        return jwtUtil.generateAccessTokenBuilder()
            .setSubject(String.valueOf(account.getID()))
            .setId(sessionID)
            .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
            .claim("roles",account.getRoles().toArray())
            .compact();
    }

    private ResponseEntity<Object> createSession(Account account) {
        String sessionID = sessionService.createSession(String.valueOf(account.getID()));;
        String refreshToken = generateRefreshToken(account, sessionID);

        refreshTokenRepository.save(sessionID, refreshToken);

        return ResponseEntity.ok()
            .header(
                HttpHeaders.COOKIE,
                generateAccessTokenCookie(generateAccessToken(account,sessionID)).toString())
            .header(
                HttpHeaders.COOKIE,
                generateRefreshTokenCookie(refreshToken).toString())
            .body(new SigninResponseMessage(
                account.getID(),
                account.getRoles()));
    }
}
