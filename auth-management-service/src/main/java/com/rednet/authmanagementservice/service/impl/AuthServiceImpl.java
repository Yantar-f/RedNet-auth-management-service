package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.exception.OccupiedValuesException;
import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.payload.ChangePasswordRequestMessage;
import com.rednet.authmanagementservice.payload.SigninRequestMessage;
import com.rednet.authmanagementservice.payload.SignupRequestMessage;
import com.rednet.authmanagementservice.payload.SimpleResponseMessage;
import com.rednet.authmanagementservice.payload.VerifyEmailRequestMessage;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import com.rednet.authmanagementservice.service.ActivationCodeGenerator;
import com.rednet.authmanagementservice.service.AuthService;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final RegistrationRepository registrationRepository;
    private final PasswordEncoder passwordEncoder;
    private final String accessTokenCookieName;


    private final JwtParser refreshTokenParser;
    private final JwtParser registrationTokenParser;
    private final String accessTokenCookiePath;
    private final String refreshTokenCookiePath;
    private final String refreshTokenCookieName;
    private final ActivationCodeGenerator activationCodeGenerator;

    @Autowired
    public AuthServiceImpl(
        AccountRepository accountRepository,
        RegistrationRepository registrationRepository, PasswordEncoder passwordEncoder,
        @Value("${rednet.app.access-token-cookie-name}") String accessTokenCookieName,
        @Qualifier("registrationTokenBuilder") JwtBuilder registrationTokenBuilder,
        @Qualifier("registrationTokenParser") JwtParser registrationTokenParser,
        @Value("${rednet.app.access-token-cookie-path}") String accessTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-name}") String refreshTokenCookiePath,
        @Value("${rednet.app.refresh-token-cookie-path}")String refreshTokenCookieName,
        @Qualifier("refreshTokenParser") JwtParser refreshTokenParser,
        @Qualifier("accessTokenBuilder") JwtBuilder accessTokenBuilder,
        @Qualifier("refreshTokenBuilder") JwtBuilder refreshTokenBuilder,
        ActivationCodeGenerator activationCodeGenerator
    ) {
        this.accountRepository = accountRepository;
        this.registrationRepository = registrationRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenCookieName = accessTokenCookieName;
        this.registrationTokenParser = registrationTokenParser;
        this.refreshTokenCookiePath = refreshTokenCookiePath;
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.refreshTokenParser = refreshTokenParser;
        this.accessTokenCookiePath = accessTokenCookiePath;
        this.activationCodeGenerator = activationCodeGenerator;
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
        String registrationKey = UUID.randomUUID().toString();

        registrationRepository.save(registrationKey, new Registration(
            String.valueOf(activationCode),
            requestMessage.getUsername(),
            passwordEncoder.encode(requestMessage.getPassword()),
            requestMessage.getEmail(),
            requestMessage.getSecretWord()
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
