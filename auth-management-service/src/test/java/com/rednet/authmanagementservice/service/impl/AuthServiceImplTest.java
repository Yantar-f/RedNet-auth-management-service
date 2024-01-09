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
import org.apache.commons.lang.RandomStringUtils;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import static com.rednet.authmanagementservice.config.EnumRoles.ROLE_USER;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class AuthServiceImplTest {
    private static final int TEST_REPETITIONS_COUNT = 3;

    Random  rand = new Random();
    int     stringLengthBound = 200;

    private final AccountRepository       accountRepository         = mock(AccountRepository.class);
    private final RegistrationRepository  registrationRepository    = mock(RegistrationRepository.class);
    private final ActivationCodeGenerator activationCodeGenerator   = mock(ActivationCodeGenerator.class);
    private final TokenIDGenerator  tokenIDGenerator  = mock(TokenIDGenerator.class);
    private final PasswordEncoder   passwordEncoder   = mock(PasswordEncoder.class);
    private final SessionService    sessionService    = mock(SessionService.class);
    private final EmailService      emailService      = mock(EmailService.class);
    private final JwtUtil           jwtUtil           = mock(JwtUtil.class);

    private final AuthService sut = new AuthServiceImpl(
        accountRepository,
        registrationRepository,
        activationCodeGenerator,
        tokenIDGenerator,
        passwordEncoder,
        sessionService,
        emailService,
        jwtUtil
    );

    private final String expectedUserID             = String.valueOf(rand.nextInt());
    private final String expectedUsername           = randString();
    private final String expectedPassword           = randString();
    private final String expectedEncodedPassword    = randString();
    private final String expectedEmail              = randString();
    private final String expectedSecretWord         = randString();
    private final String expectedActivationCode     = randString();
    private final String expectedTokenID            = randString();
    private final String expectedAccessToken        = randString();
    private final String expectedRefreshToken       = randString();
    private final String expectedRegistrationID     = randString();
    private final String regTokenSecretKey          = "g6rwN6RboZLiFI6LsrOWuNWDpyUoBkDfZDjMt0f3vA8n+TvRLLzG6Z5QQwqA4y4h";

    private final String[] expectedRoles = new String[]{ROLE_USER.name()};

    private final JwtParser regTokenParser = Jwts.parserBuilder()
        .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(regTokenSecretKey)))
        .build();
    private final Instant expectedCreatedAt = Instant.now();

    @Test
    void signup() {
        SignupRequestBody expectedBody = new SignupRequestBody(
            expectedUsername,
            expectedEmail,
            expectedPassword,
            expectedSecretWord
        );

        when(accountRepository.findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail)))
                .thenReturn(Optional.empty());

        when(passwordEncoder.encode(eq(expectedPassword)))
                .thenReturn(expectedEncodedPassword);

        when(activationCodeGenerator.generate())
                .thenReturn(expectedActivationCode);

        when(tokenIDGenerator.generate())
                .thenReturn(expectedTokenID);

        when(jwtUtil.generateRegistrationTokenBuilder())
                .thenReturn(generateTestRegTokenBuilder());

        RegistrationCredentials registrationCredentials = sut.signup(expectedBody);
        Claims claims = regTokenParser.parseClaimsJws(registrationCredentials.registrationToken()).getBody();

        assertEquals("registration", claims.get("test"));
        assertEquals(expectedTokenID, claims.getId());
        assertNotNull(claims.getSubject());

        verify(emailService, atLeastOnce())
                .sendRegistrationActivationMessage(eq(expectedEmail), eq(expectedActivationCode));

        verify(registrationRepository)
                .save(any(), argThat(reg ->
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

        when(accountRepository.findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail)))
                .thenReturn(Optional.of(expectedAccount));

        assertThrows(OccupiedValueException.class, () -> sut.signup(expectedBody));
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

        SessionDTO expectedSessionDTO = new SessionDTO(expectedSession);
        SigninRequestBody body = new SigninRequestBody(expectedUsername, expectedPassword);

        when(accountRepository.findEagerByUsernameOrEmail(eq(expectedUsername), eq(expectedUsername)))
                .thenReturn(Optional.of(expectedAccount));

        when(passwordEncoder.matches(eq(expectedPassword), eq(expectedEncodedPassword)))
                .thenReturn(true);

        when(sessionService.createSession(any(), any()))
                .thenReturn(expectedSession);

        SessionDTO actualSessionDTO = sut.signin(body);

        assertEquals(expectedSessionDTO, actualSessionDTO);

        verify(sessionService)
                .createSession(
                        eq(expectedUserID),
                        argThat(actualRoles -> compareStringArraysContent(expectedRoles, actualRoles))
                );
    }

    @Test
    void signin_InvalidAccountData_InvalidUserIdentifier() {
        SigninRequestBody body = new SigninRequestBody(expectedUsername, expectedPassword);

        when(accountRepository.findEagerByUsernameOrEmail(eq(expectedUsername), eq(expectedUsername)))
                .thenReturn(Optional.empty());

        assertThrows(InvalidAccountDataException.class, () -> sut.signin(body));
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

        when(accountRepository.findEagerByUsernameOrEmail(eq(expectedUsername), eq(expectedUsername)))
                .thenReturn(Optional.of(expectedAccount));

        when(passwordEncoder.matches(eq(expectedPassword), eq(expectedEncodedPassword))).thenReturn(false);

        assertThrows(InvalidAccountDataException.class, () -> sut.signin(body));
    }

    @Test
    void signout() {
        sut.signout(expectedRefreshToken);

        verify(sessionService)
                .deleteSession(eq(expectedRefreshToken));
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

        String oldRefreshToken = randString();
        SessionDTO expectedSessionDTO = new SessionDTO(expectedSession);

        when(sessionService.refreshSession(eq(oldRefreshToken)))
                .thenReturn(expectedSession);

        SessionDTO actualSessionDTO = sut.refreshTokens(oldRefreshToken);

        assertEquals(expectedSessionDTO, actualSessionDTO);

        verify(sessionService)
                .refreshSession(eq(oldRefreshToken));
    }

    @Test
    void verifyEmail() {
        Account expectedUnsavedAccount = new Account(
                expectedUsername,
                expectedEncodedPassword,
                expectedEmail,
                expectedSecretWord,
                Set.of(new Role(ROLE_USER))
        );

        Account expectedAccount = new Account(
            expectedUsername,
            expectedEncodedPassword,
            expectedEmail,
            expectedSecretWord,
            Set.of(new Role(ROLE_USER))
        );

        expectedAccount.setID(Long.parseLong(expectedUserID));

        RegistrationVerifications expectedBody = new RegistrationVerifications(
                expectedRegistrationID,
                expectedActivationCode
        );

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

        SessionDTO expectedSessionDTO = new SessionDTO(expectedSession);

        when(registrationRepository.find(eq(expectedRegistrationID)))
                .thenReturn(Optional.of(expectedRegistration));

        when(accountRepository.findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail)))
                .thenReturn(Optional.empty());

        when(accountRepository.save(eq(expectedUnsavedAccount)))
                .thenReturn(expectedAccount);

        when(sessionService.createSession(any(), any()))
                .thenReturn(expectedSession);

        SessionDTO actualSessionDTO = sut.verifyEmail(expectedBody);

        assertEquals(expectedSessionDTO, actualSessionDTO);

        verify(registrationRepository)
                .delete(eq(expectedRegistrationID));

        verify(accountRepository)
                .save(eq(expectedUnsavedAccount));

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

        when(registrationRepository.find(eq(expectedRegistrationID)))
                .thenReturn(Optional.of(expectedRegistration));

        assertThrows(InvalidRegistrationDataException.class, () -> sut.verifyEmail(expectedBody));
    }

    @RepeatedTest(TEST_REPETITIONS_COUNT)
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

        when(registrationRepository.find(any()))
                .thenReturn(Optional.of(expectedRegistration));

        when(accountRepository.findByUsernameOrEmail(any(), any()))
                .thenReturn(Optional.of(expectedAccount));

        assertThrows(OccupiedValueException.class, () -> sut.verifyEmail(expectedBody));

        verify(registrationRepository)
                .find(eq(expectedRegistrationID));

        verify(registrationRepository)
                .delete(eq(expectedRegistrationID));

        verify(accountRepository)
                .findByUsernameOrEmail(eq(expectedUsername), eq(expectedEmail));
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

        when(activationCodeGenerator.generate())
                .thenReturn(expectedActivationCode);

        when(tokenIDGenerator.generate())
                .thenReturn(expectedTokenID);

        when(jwtUtil.getRegistrationTokenParser())
                .thenReturn(regTokenParser);

        when(jwtUtil.generateRegistrationTokenBuilder())
                .thenReturn(generateTestRegTokenBuilder());

        when(registrationRepository.find(any()))
                .thenReturn(Optional.of(expectedRegistration));

        assertDoesNotThrow(() -> {
            String newRegToken = sut.resendEmailVerification(expectedRegistrationToken);

            Claims claims = regTokenParser.parseClaimsJws(newRegToken).getBody();

            assertEquals("registration", claims.get("test"));
            assertEquals(expectedRegistrationID, claims.getSubject());
            assertNotNull(claims.getSubject());
        });

        verify(activationCodeGenerator)
                .generate();

        verify(tokenIDGenerator)
                .generate();

        verify(jwtUtil)
                .getRegistrationTokenParser();

        verify(jwtUtil)
                .generateRegistrationTokenBuilder();

        verify(registrationRepository)
                .find(eq(expectedRegistrationID));

        verify(registrationRepository)
                .save(
                        eq(expectedRegistrationID),
                        argThat(reg ->
                                reg.getUsername().equals(expectedUsername) &&
                                reg.getPassword().equals(expectedEncodedPassword) &&
                                reg.getEmail().equals(expectedEmail) &&
                                reg.getSecretWord().equals(expectedSecretWord) &&
                                reg.getTokenID().equals(expectedTokenID)
                        )
                );

        verify(emailService)
                .sendRegistrationActivationMessage(eq(expectedEmail), any());
    }

    @Test
    void resendEmailVerification_InvalidRegistrationToken() {
        String expectedRegToken = "reg-token";

        when(jwtUtil.getRegistrationTokenParser()).thenReturn(regTokenParser);

        assertThrows(InvalidTokenException.class, () -> sut.resendEmailVerification(expectedRegToken));

        verify(jwtUtil)
                .getRegistrationTokenParser();
    }

    @Test
    void resendEmailVerification_InvalidRegistrationToken_InvalidRegistrationID() {
        String expectedRegToken = generateTestRegTokenBuilder().setSubject("id1").compact();

        when(jwtUtil.getRegistrationTokenParser())
                .thenReturn(regTokenParser);

        when(registrationRepository.find(any()))
                .thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class, () -> sut.resendEmailVerification(expectedRegToken));

        verify(jwtUtil)
                .getRegistrationTokenParser();

        verify(registrationRepository)
                .find(eq("id1"));
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

    private int randStringLength() {
        return rand.nextInt(stringLengthBound - 1) + 1;
    }

    private String randString() {
        return RandomStringUtils.random(randStringLength());
    }
}