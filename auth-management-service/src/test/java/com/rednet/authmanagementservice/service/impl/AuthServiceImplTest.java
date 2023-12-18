package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.entity.Role;
import com.rednet.authmanagementservice.dto.SessionDTO;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.impl.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.impl.InvalidRegistrationDataException;
import com.rednet.authmanagementservice.exception.impl.InvalidTokenException;
import com.rednet.authmanagementservice.exception.impl.OccupiedValueException;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerifications;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.service.EmailService;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.util.JwtUtil;
import com.rednet.authmanagementservice.util.TokenIDGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static com.rednet.authmanagementservice.config.EnumRoles.ROLE_USER;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceImplTest {
    AccountRepository       accountRepository= mock(AccountRepository.class);
    RegistrationRepository  registrationRepository = mock(RegistrationRepository.class);
    ActivationCodeGenerator activationCodeGenerator = mock(ActivationCodeGenerator.class);
    TokenIDGenerator        tokenIDGenerator = mock(TokenIDGenerator.class);
    PasswordEncoder         passwordEncoder = mock(PasswordEncoder.class);
    SessionService          sessionService = mock(SessionService.class);
    EmailService            emailService = mock(EmailService.class);
    JwtUtil                 jwtUtil = mock(JwtUtil.class);

    AuthService authService = new AuthServiceImpl(
        accountRepository,
        registrationRepository,
        activationCodeGenerator,
        tokenIDGenerator,
        passwordEncoder,
        sessionService,
        emailService,
        jwtUtil
    );

    String expectedUserID = "123456";
    String expectedUsername = "username";
    String expectedPassword = "password";
    String expectedEncodedPassword = "encodedPassword";
    String expectedEmail = "email";
    String expectedSecretWord = "secret";
    String expectedActivationCode = "activation";
    String expectedTokenID = "reg-token-id";
    String expectedAccessToken = "a-token";
    String expectedRefreshToken = "r-token";
    String expectedRegistrationID = "reg-id";
    String regTokenSecretKey = "g6rwN6RboZLiFI6LsrOWuNWDpyUoBkDfZDjMt0f3vA8n+TvRLLzG6Z5QQwqA4y4h";

    String[] expectedRoles = new String[]{ROLE_USER.name()};

    JwtParser regTokenParser = Jwts.parserBuilder()
        .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(regTokenSecretKey)))
        .build();
    Instant expectedCreatedAt = Instant.now();

    @Test
    void signup() {
        SignupRequestBody expectedBody = new SignupRequestBody(
            expectedUsername,
            expectedEmail,
            expectedPassword,
            expectedSecretWord
        );

        when(accountRepository.findByUsernameOrEmail(any(), any())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(any())).thenReturn(expectedEncodedPassword);
        when(activationCodeGenerator.generate()).thenReturn(expectedActivationCode);
        when(tokenIDGenerator.generate()).thenReturn(expectedTokenID);
        when(jwtUtil.generateRegistrationTokenBuilder()).thenReturn(generateTestRegTokenBuilder());

        assertDoesNotThrow(() -> {
            RegistrationCredentials registrationCredentials = authService.signup(expectedBody);

            Claims claims = regTokenParser.parseClaimsJws(registrationCredentials.registrationToken()).getBody();

            assertEquals("registration", claims.get("test"));
            assertEquals(expectedTokenID, claims.getId());
            assertNotNull(claims.getSubject());
        });

        verify(accountRepository).findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail));
        verify(passwordEncoder).encode(eq(expectedPassword));
        verify(activationCodeGenerator).generate();
        verify(tokenIDGenerator).generate();

        verify(emailService, atLeastOnce()).sendRegistrationActivationMessage(
            eq(expectedEmail),
            eq(expectedActivationCode)
        );

        verify(registrationRepository).save(any(), argThat(reg ->
            reg.getUsername().equals(expectedUsername) &&
            reg.getPassword().equals(expectedEncodedPassword) &&
            reg.getEmail().equals(expectedEmail) &&
            reg.getSecretWord().equals(expectedSecretWord) &&
            reg.getActivationCode().equals(expectedActivationCode) &&
            reg.getTokenID().equals(expectedTokenID)
        ));
    }

    @Test
    void signup_OccupiedValues() {
        Account expectedAccount = new Account(
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord,
            Set.of(new Role(ROLE_USER))
        );

        expectedAccount.setID(Long.parseLong(expectedUserID));

        SignupRequestBody expectedBody = new SignupRequestBody(
            expectedUsername,
            expectedEmail,
            expectedPassword,
            expectedSecretWord
        );

        when(accountRepository.findByUsernameOrEmail(any(), any())).thenReturn(Optional.of(expectedAccount));

        assertThrows(OccupiedValueException.class, () -> authService.signup(expectedBody));

        verify(accountRepository).findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail));
        verify(passwordEncoder, never()).encode(any());
        verify(activationCodeGenerator, never()).generate();
        verify(tokenIDGenerator, never()).generate();
        verify(emailService, never()).sendRegistrationActivationMessage(any(), any());
        verify(registrationRepository, never()).save(any(), any());
    }

    @Test
    void signin() {
        Account expectedAccount = new Account(
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord,
            Set.of(new Role(ROLE_USER))
        );

        expectedAccount.setID(Long.parseLong(expectedUserID));

        Session expectedSession = new Session(
            expectedUserID,
            expectedRoles,
            expectedCreatedAt,
            expectedAccessToken,
            expectedRefreshToken,
            expectedTokenID
        );

        SigninRequestBody body = new SigninRequestBody(expectedUsername, expectedPassword);

        when(accountRepository.findEagerByUsernameOrEmail(any(), any())).thenReturn(Optional.of(expectedAccount));
        when(passwordEncoder.matches(any(), any())).thenReturn(true);
        when(sessionService.createSession(any(), any())).thenReturn(expectedSession);

        assertDoesNotThrow(() -> {
            SessionDTO sessionDTO = authService.signin(body);

            assertEquals(expectedUserID, sessionDTO.getUserID());
            assertEquals(expectedAccessToken, sessionDTO.getAccessToken());
            assertEquals(expectedRefreshToken, sessionDTO.getRefreshToken());
            assertTrue(compareStringArraysContent(expectedRoles, sessionDTO.getRoles()));
        });

        verify(accountRepository).findEagerByUsernameOrEmail(eq(expectedUsername), eq(expectedUsername));
        verify(passwordEncoder).matches(eq(expectedPassword), eq(expectedEncodedPassword));

        verify(sessionService).createSession(
            eq(expectedUserID),
            argThat(actualRoles -> compareStringArraysContent(expectedRoles, actualRoles))
        );
    }

    @Test
    void signin_InvalidAccountData_InvalidUserIdentifier() {
        SigninRequestBody body = new SigninRequestBody(expectedUsername, expectedPassword);

        when(accountRepository.findEagerByUsernameOrEmail(any(), any())).thenReturn(Optional.empty());

        assertThrows(InvalidAccountDataException.class, () -> authService.signin(body));

        verify(accountRepository).findEagerByUsernameOrEmail(eq(expectedUsername), eq(expectedUsername));
        verify(passwordEncoder, never()).matches(any(), any());
        verify(sessionService, never()).createSession(any(), any());
    }

    @Test
    void signin_InvalidAccountData_InvalidPassword() {
        Account expectedAccount = new Account(
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord,
            Set.of(new Role(ROLE_USER))
        );

        expectedAccount.setID(Long.parseLong(expectedUserID));

        SigninRequestBody body = new SigninRequestBody(expectedUsername, expectedPassword);

        when(accountRepository.findEagerByUsernameOrEmail(any(), any())).thenReturn(Optional.of(expectedAccount));
        when(passwordEncoder.matches(any(), any())).thenReturn(false);

        assertThrows(InvalidAccountDataException.class, () -> authService.signin(body));

        verify(accountRepository).findEagerByUsernameOrEmail(eq(expectedUsername), eq(expectedUsername));
        verify(passwordEncoder).matches(eq(expectedPassword), eq(expectedEncodedPassword));
        verify(sessionService, never()).createSession(any(), any());
    }

    @Test
    void signout() {
        assertDoesNotThrow(() -> authService.signout(expectedRefreshToken));

        verify(sessionService).deleteSession(eq(expectedRefreshToken));
    }

    @Test
    void refreshTokens() {
        Session expectedSession = new Session(
            expectedUserID,
            expectedRoles,
            expectedCreatedAt,
            expectedAccessToken,
            expectedRefreshToken,
            expectedTokenID
        );

        when(sessionService.refreshSession(any())).thenReturn(expectedSession);

        assertDoesNotThrow(() -> {
            SessionDTO sessionDTO = authService.refreshTokens("old-token");

            assertEquals(expectedUserID, sessionDTO.getUserID());
            assertEquals(expectedAccessToken, sessionDTO.getAccessToken());
            assertEquals(expectedRefreshToken, sessionDTO.getRefreshToken());
            assertEquals(expectedRoles.length, sessionDTO.getRoles().length);
            assertTrue(compareStringArraysContent(expectedRoles, sessionDTO.getRoles()));
        });

        verify(sessionService).refreshSession(eq("old-token"));
    }

    @Test
    void verifyEmail() {
        Account expectedAccount = new Account(
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord,
            Set.of(new Role(ROLE_USER))
        );

        expectedAccount.setID(Long.parseLong(expectedUserID));

        RegistrationVerifications expectedBody = new RegistrationVerifications(expectedRegistrationID, expectedActivationCode);

        Registration expectedRegistration = new Registration(
            expectedActivationCode,
            expectedTokenID,
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord
        );

        Session expectedSession = new Session(
            expectedUserID,
            expectedRoles,
            expectedCreatedAt,
            expectedAccessToken,
            expectedRefreshToken,
            expectedTokenID
        );

        when(registrationRepository.find(any())).thenReturn(Optional.of(expectedRegistration));
        when(accountRepository.findByUsernameOrEmail(any(), any())).thenReturn(Optional.empty());
        when(accountRepository.save(any())).thenReturn(expectedAccount);
        when(sessionService.createSession(any(), any())).thenReturn(expectedSession);

        assertDoesNotThrow(() -> {
            SessionDTO actualSessionDTO = authService.verifyEmail(expectedBody);

            assertEquals(expectedUserID, actualSessionDTO.getUserID());
            assertEquals(expectedAccessToken, actualSessionDTO.getAccessToken());
            assertEquals(expectedRefreshToken, actualSessionDTO.getRefreshToken());
            assertTrue(compareStringArraysContent(expectedRoles, actualSessionDTO.getRoles()));
        });

        verify(registrationRepository).find(eq(expectedRegistrationID));
        verify(accountRepository).findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail));

        verify(accountRepository).save(argThat(account ->
            account.getUsername().equals(expectedUsername) &&
            account.getEmail().equals(expectedEmail) &&
            account.getPassword().equals(expectedEncodedPassword) &&
            account.getSecretWord().equals(expectedSecretWord) &&
            compareStringArraysContent(
                expectedRoles,
                account.getRoles().stream().map(Role::getDesignation).toArray(String[]::new)
            )
        ));

        verify(sessionService).createSession(
            eq(expectedUserID),
            argThat(actualRoles -> compareStringArraysContent(expectedRoles, actualRoles))
        );
    }

    @Test
    void verifyEmail_InvalidActivationCode() {
        RegistrationVerifications expectedBody = new RegistrationVerifications(expectedRegistrationID, expectedActivationCode);

        Registration expectedRegistration = new Registration(
            "validCode",
            expectedTokenID, expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord
        );

        when(registrationRepository.find(any())).thenReturn(Optional.of(expectedRegistration));

        assertThrows(InvalidRegistrationDataException.class, () -> authService.verifyEmail(expectedBody));

        verify(registrationRepository).find(eq(expectedRegistrationID));
        verify(accountRepository, never()).save(any());
        verify(sessionService, never()).createSession(any(), any());
    }

    @Test
    void verifyEmail_OccupiedValues() {
        Account expectedAccount = new Account(
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord,
            Set.of(new Role(ROLE_USER))
        );

        expectedAccount.setID(Long.parseLong(expectedUserID));

        RegistrationVerifications expectedBody = new RegistrationVerifications(expectedRegistrationID, expectedActivationCode);

        Registration expectedRegistration = new Registration(
            expectedActivationCode,
            expectedTokenID, expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord
        );

        when(registrationRepository.find(any())).thenReturn(Optional.of(expectedRegistration));
        when(accountRepository.findByUsernameOrEmail(any(), any())).thenReturn(Optional.of(expectedAccount));

        assertThrows(OccupiedValueException.class, () -> authService.verifyEmail(expectedBody));

        verify(registrationRepository).find(eq(expectedRegistrationID));
        verify(accountRepository).findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail));
        verify(sessionService, never()).createSession(any(), any());
    }

    @Test
    void resendEmailVerification() {
        String expectedRegistrationToken = generateTestRegTokenBuilder()
            .setSubject(expectedRegistrationID)
            .setId("oldID")
            .compact();

        Registration expectedRegistration = new Registration(
            expectedActivationCode,
            "oldID",
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord
        );

        when(activationCodeGenerator.generate()).thenReturn(expectedActivationCode);
        when(tokenIDGenerator.generate()).thenReturn(expectedTokenID);
        when(jwtUtil.getRegistrationTokenParser()).thenReturn(regTokenParser);
        when(jwtUtil.generateRegistrationTokenBuilder()).thenReturn(generateTestRegTokenBuilder());
        when(registrationRepository.find(any())).thenReturn(Optional.of(expectedRegistration));

        assertDoesNotThrow(() -> {
            String newRegToken = authService.resendEmailVerification(expectedRegistrationToken);

            Claims claims = regTokenParser.parseClaimsJws(newRegToken).getBody();

            assertEquals("registration", claims.get("test"));
            assertEquals(expectedRegistrationID, claims.getSubject());
            assertNotNull(claims.getSubject());
        });

        verify(activationCodeGenerator).generate();
        verify(tokenIDGenerator).generate();
        verify(jwtUtil).getRegistrationTokenParser();
        verify(jwtUtil).generateRegistrationTokenBuilder();
        verify(registrationRepository).find(eq(expectedRegistrationID));

        verify(registrationRepository).save(eq(expectedRegistrationID), argThat(reg ->
            reg.getUsername().equals(expectedUsername) &&
            reg.getPassword().equals(expectedEncodedPassword) &&
            reg.getEmail().equals(expectedEmail) &&
            reg.getSecretWord().equals(expectedSecretWord) &&
            reg.getTokenID().equals(expectedTokenID)
        ));

        verify(emailService).sendRegistrationActivationMessage(eq(expectedEmail), any());
    }

    @Test
    void resendEmailVerification_InvalidRegistrationToken() {
        String expectedRegToken = "reg-token";

        when(jwtUtil.getRegistrationTokenParser()).thenReturn(regTokenParser);

        assertThrows(InvalidTokenException.class, () -> authService.resendEmailVerification(expectedRegToken));

        verify(jwtUtil).getRegistrationTokenParser();
        verify(activationCodeGenerator, never()).generate();
        verify(tokenIDGenerator, never()).generate();
        verify(jwtUtil, never()).generateRegistrationTokenBuilder();
        verify(registrationRepository, never()).find(any());
        verify(emailService, never()).sendRegistrationActivationMessage(any(), any());
    }

    @Test
    void resendEmailVerification_InvalidRegistrationToken_InvalidRegistrationID() {
        String expectedRegToken = generateTestRegTokenBuilder().setSubject("id1").compact();

        when(jwtUtil.getRegistrationTokenParser()).thenReturn(regTokenParser);
        when(registrationRepository.find(any())).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class, () -> authService.resendEmailVerification(expectedRegToken));

        verify(jwtUtil).getRegistrationTokenParser();
        verify(registrationRepository).find(eq("id1"));
        verify(activationCodeGenerator, never()).generate();
        verify(tokenIDGenerator, never()).generate();
        verify(jwtUtil, never()).generateRegistrationTokenBuilder();
        verify(emailService, never()).sendRegistrationActivationMessage(any(), any());
    }

    private boolean compareStringArraysContent(String[] expectedRoles, String[] roles) {
        if (expectedRoles.length != roles.length) return false;

        for (String role : roles) if ( ! Arrays.asList(expectedRoles).contains(role)) return false;

        return true;
    }

    private JwtBuilder generateTestRegTokenBuilder() {
        return Jwts.builder()
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(regTokenSecretKey)))
            .claim("test", "registration");
    }
}