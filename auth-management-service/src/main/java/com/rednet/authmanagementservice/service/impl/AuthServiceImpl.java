package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.payload.ChangePasswordRequestMessage;
import com.rednet.authmanagementservice.payload.SigninRequestMessage;
import com.rednet.authmanagementservice.payload.SignupRequestMessage;
import com.rednet.authmanagementservice.payload.SimpleResponseMessage;
import com.rednet.authmanagementservice.payload.VerifyEmailRequestMessage;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.service.AuthService;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final String accessTokenCookieName;


    private final JwtParser refreshTokenParser;
    private final JwtBuilder accessTokenBuilder;
    private final JwtBuilder refreshTokenBuilder;
    private final String accessTokenCookiePath;
    private final String refreshTokenCookiePath;
    private final String refreshTokenCookieName;

    @Autowired
    public AuthServiceImpl(
        AccountRepository accountRepository,
        PasswordEncoder passwordEncoder,
        @Value("${rednet.app.access-token-cookie-name}") String accessTokenCookieName,
        @Value("${rednet.app.access-token-cookie-path}") String accessTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-name}") String refreshTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-path}")String refreshTokenCookieName,
        @Value("${refreshTokenParser}") JwtParser refreshTokenParser,
        @Value("${accessTokenBuilder}") JwtBuilder accessTokenBuilder,
        @Value("${refreshTokenBuilder}") JwtBuilder refreshTokenBuilder
    ) {
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenCookieName = accessTokenCookieName;
        this.refreshTokenCookiePath = refreshTokenCookiePath;
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.refreshTokenParser = refreshTokenParser;
        this.accessTokenBuilder = accessTokenBuilder;
        this.refreshTokenBuilder = refreshTokenBuilder;
        this.accessTokenCookiePath = accessTokenCookiePath;
    }

    @Override
    public ResponseEntity<Object> signup(SignupRequestMessage requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.getUsername(), requestMessage.getEmail())
            .orElse(null);

        if (account != null) {
            StringBuilder errorMessageBuilder = new StringBuilder("Occupied values: ");

            if (requestMessage.getUsername().equals(account.getUsername())) {
                errorMessageBuilder.append("username");
                if (requestMessage.getEmail().equals(account.getEmail())) {
                    errorMessageBuilder.append(", email");
                }
            } else {
                errorMessageBuilder.append("email");
            }

            throw new OccupiedValueException(errorMessageBuilder.toString());
        }

        accountRepository.save(new Account(
            requestMessage.getUsername(),
            passwordEncoder.encode(requestMessage.getPassword()),
            requestMessage.getEmail(),
            requestMessage.getSecretWord(),
            new HashSet<>(){{add(EnumRoles.ROLE_USER);}}
        ));

        ///
        /// create email verification token and activation code
        ///

        return null;
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
                generateCleaningCookie(accessTokenCookieName,accessTokenCookiePath).toString()
            )
            .header(
                HttpHeaders.COOKIE,
                generateCleaningCookie(refreshTokenCookieName,refreshTokenCookiePath).toString()
            )
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

}
