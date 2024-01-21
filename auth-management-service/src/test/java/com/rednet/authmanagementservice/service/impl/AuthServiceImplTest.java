package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.RolesEnum;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.InvalidRegistrationDataException;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import com.rednet.authmanagementservice.model.AccountCreationData;
import com.rednet.authmanagementservice.model.AccountUniqueFields;
import com.rednet.authmanagementservice.model.AccountUniqueFieldsOccupancy;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationCreationData;
import com.rednet.authmanagementservice.model.RegistrationTokenClaims;
import com.rednet.authmanagementservice.model.RegistrationVerificationData;
import com.rednet.authmanagementservice.model.SessionCreationData;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.service.AccountService;
import com.rednet.authmanagementservice.service.EmailService;
import com.rednet.authmanagementservice.service.RegistrationService;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.util.TokenIDGenerator;
import com.rednet.authmanagementservice.util.TokenUtil;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.instancio.Instancio.create;
import static org.instancio.Instancio.ofSet;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceImplTest {
    private final AccountService accountService = mock(AccountService.class);
    private final RegistrationService registrationService = mock(RegistrationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final EmailService emailService = mock(EmailService.class);
    private final ActivationCodeGenerator activationCodeGenerator = mock(ActivationCodeGenerator.class);
    private final TokenIDGenerator tokenIDGenerator = mock(TokenIDGenerator.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final TokenUtil tokenUtil = mock(TokenUtil.class);

    private final AuthServiceImpl sut = new AuthServiceImpl(
            accountService,
            registrationService,
            sessionService,
            emailService,
            activationCodeGenerator,
            tokenIDGenerator,
            passwordEncoder,
            tokenUtil
    );

    @Test
    public void Registration_with_unique_username_and_email_is_successful() {
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedEncodedPassword = create(String.class);
        String expectedSecretWord = create(String.class);
        String expectedEncodedSecretWord = create(String.class);
        String expectedRegistrationID = create(String.class);
        String expectedRegistrationToken = create(String.class);
        String expectedTokenID = create(String.class);
        String expectedActivationCode = create(String.class);
        boolean expectedUsernameOccupancy = false;
        boolean expectedEmailOccupancy = false;

        SignupRequestBody request = new SignupRequestBody(
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        RegistrationCredentials expectedCredentials = new RegistrationCredentials(
                expectedRegistrationID,
                expectedRegistrationToken
        );

        RegistrationTokenClaims expectedTokenClaims = new RegistrationTokenClaims(
                expectedTokenID,
                expectedRegistrationID
        );

        RegistrationCreationData expectedRegistrationCreationData = new RegistrationCreationData(
                expectedActivationCode,
                expectedTokenID,
                expectedUsername,
                expectedEmail,
                expectedEncodedPassword,
                expectedEncodedSecretWord
        );

        Registration expectedRegistration = new Registration(
                expectedRegistrationID,
                expectedRegistrationID,
                expectedActivationCode,
                expectedUsername,
                expectedEmail,
                expectedEncodedPassword,
                expectedEncodedSecretWord
        );

        AccountUniqueFields expectedUniqueFields = new AccountUniqueFields(expectedUsername, expectedEmail);

        AccountUniqueFieldsOccupancy expectedOccupancy = new AccountUniqueFieldsOccupancy(
                expectedUsername,
                expectedEmail,
                expectedUsernameOccupancy,
                expectedEmailOccupancy
        );

        when(accountService.checkAccountUniqueFieldsOccupancy(eq(expectedUniqueFields)))
                .thenReturn(expectedOccupancy);

        when(passwordEncoder.encode(eq(expectedPassword)))
                .thenReturn(expectedEncodedPassword);

        when(passwordEncoder.encode(eq(expectedSecretWord)))
                .thenReturn(expectedEncodedSecretWord);

        when(activationCodeGenerator.generate())
                .thenReturn(expectedActivationCode);

        when(tokenIDGenerator.generate())
                .thenReturn(expectedTokenID);

        when(tokenUtil.generateRegistrationToken(eq(expectedTokenClaims)))
                .thenReturn(expectedRegistrationToken);

        when(registrationService.createRegistration(eq(expectedRegistrationCreationData)))
                .thenReturn(expectedRegistration);

        RegistrationCredentials actualCredentials = sut.signup(request);

        assertEquals(expectedCredentials, actualCredentials);

        verify(registrationService)
                .createRegistration(eq(expectedRegistrationCreationData));

        verify(emailService)
                .sendRegistrationActivationMessage(eq(expectedEmail), eq(expectedActivationCode));
    }

    @Test
    public void Registration_with_not_unique_username_is_not_successful() {
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedSecretWord = create(String.class);
        boolean expectedUsernameOccupancy = true;
        boolean expectedEmailOccupancy = false;

        SignupRequestBody request = new SignupRequestBody(
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        AccountUniqueFields expectedUniqueFields = new AccountUniqueFields(expectedUsername, expectedEmail);

        AccountUniqueFieldsOccupancy expectedOccupancy = new AccountUniqueFieldsOccupancy(
                expectedUsername,
                expectedEmail,
                expectedUsernameOccupancy,
                expectedEmailOccupancy
        );

        when(accountService.checkAccountUniqueFieldsOccupancy(eq(expectedUniqueFields)))
                .thenReturn(expectedOccupancy);

        assertThrows(OccupiedValueException.class, () -> sut.signup(request));

        verify(registrationService, never())
                .createRegistration(any());

        verify(emailService, never())
                .sendRegistrationActivationMessage(any(), any());
    }

    @Test
    public void Registration_with_not_unique_email_is_not_successful() {
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedSecretWord = create(String.class);
        boolean expectedUsernameOccupancy = false;
        boolean expectedEmailOccupancy = true;

        SignupRequestBody request = new SignupRequestBody(
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        AccountUniqueFields expectedUniqueFields = new AccountUniqueFields(expectedUsername, expectedEmail);

        AccountUniqueFieldsOccupancy expectedOccupancy = new AccountUniqueFieldsOccupancy(
                expectedUsername,
                expectedEmail,
                expectedUsernameOccupancy,
                expectedEmailOccupancy
        );

        when(accountService.checkAccountUniqueFieldsOccupancy(eq(expectedUniqueFields)))
                .thenReturn(expectedOccupancy);

        assertThrows(OccupiedValueException.class, () -> sut.signup(request));

        verify(registrationService, never())
                .createRegistration(any());

        verify(emailService, never())
                .sendRegistrationActivationMessage(any(), any());
    }

    @Test
    public void Verifying_email_with_valid_activation_data_is_successful() {
        String expectedUserID = create(String.class);
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedSecretWord = create(String.class);
        String expectedRegistrationID = create(String.class);
        String expectedActivationCode = create(String.class);
        String expectedTokenID = create(String.class);
        Set<RolesEnum> expectedRoles = new HashSet<>(List.of(RolesEnum.ROLE_USER));

        RegistrationVerificationData expectedVerificationData = new RegistrationVerificationData(
                expectedRegistrationID,
                expectedActivationCode
        );

        Registration expectedRegistration = new Registration(
                expectedRegistrationID,
                expectedActivationCode,
                expectedTokenID,
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        AccountCreationData expectedAccountCreationData = new AccountCreationData(
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord,
                expectedRoles
        );

        Account expectedAccount = new Account(
                expectedUserID,
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord,
                expectedRoles
        );

        SessionCreationData expectedSessionCreationData = new SessionCreationData(
                expectedUserID,
                expectedRoles.toArray(RolesEnum[]::new)
        );

        Session expectedSession = create(Session.class);

        when(registrationService.findRegistrationByID(eq(expectedRegistrationID)))
                .thenReturn(Optional.of(expectedRegistration));

        when(accountService.createAccount(eq(expectedAccountCreationData)))
                .thenReturn(expectedAccount);

        when(sessionService.createSession(eq(expectedSessionCreationData)))
                .thenReturn(expectedSession);

        Session actualSession = sut.verifyEmail(expectedVerificationData);

        assertEquals(expectedSession, actualSession);

        verify(registrationService)
                .deleteRegistrationByID(eq(expectedRegistrationID));

        verify(accountService)
                .createAccount(eq(expectedAccountCreationData));
    }

    @Test
    void Verifying_email_with_invalid_activation_code_is_not_successful() {
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedSecretWord = create(String.class);
        String expectedRegistrationID = create(String.class);
        String expectedActivationCode = create(String.class);
        String expectedInvalidActivationCode = create(String.class);
        String expectedTokenID = create(String.class);

        RegistrationVerificationData expectedVerificationData = new RegistrationVerificationData(
                expectedRegistrationID,
                expectedInvalidActivationCode
        );

        Registration expectedRegistration = new Registration(
                expectedRegistrationID,
                expectedActivationCode,
                expectedTokenID,
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        when(registrationService.findRegistrationByID(eq(expectedRegistrationID)))
                .thenReturn(Optional.of(expectedRegistration));

        assertThrows(InvalidRegistrationDataException.class, () -> sut.verifyEmail(expectedVerificationData));

        verify(registrationService, never())
                .deleteRegistrationByID(any());

        verify(accountService, never())
                .createAccount(any());
    }

    @Test
    void Verifying_email_with_invalid_registration_id_is_not_successful() {
        String expectedInvalidRegistrationID = create(String.class);
        String expectedActivationCode = create(String.class);

        RegistrationVerificationData expectedVerificationData = new RegistrationVerificationData(
                expectedInvalidRegistrationID,
                expectedActivationCode
        );

        when(registrationService.findRegistrationByID(eq(expectedInvalidRegistrationID)))
                .thenReturn(Optional.empty());

        assertThrows(InvalidRegistrationDataException.class, () -> sut.verifyEmail(expectedVerificationData));

        verify(registrationService, never())
                .deleteRegistrationByID(any());

        verify(accountService, never())
                .createAccount(any());
    }

    @Test
    public void Resend_email_verification_with_valid_registration_token_is_successful() {
        String expectedOldRegistrationToken = create(String.class);
        String expectedNewRegistrationToken = create(String.class);
        String expectedRegistrationID = create(String.class);
        String expectedOldActivationCode = create(String.class);
        String expectedNewActivationCode = create(String.class);
        String expectedOldTokenID = create(String.class);
        String expectedNewTokenID = create(String.class);
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedSecretWord = create(String.class);

        RegistrationTokenClaims expectedOldTokenClaims = new RegistrationTokenClaims(
                expectedOldTokenID,
                expectedRegistrationID
        );

        RegistrationTokenClaims expectedNewTokenClaims = new RegistrationTokenClaims(
                expectedNewTokenID,
                expectedRegistrationID
        );

        Registration expectedRegistration = new Registration(
                expectedRegistrationID,
                expectedOldActivationCode,
                expectedOldTokenID,
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        Registration expectedUpdatedRegistration = new Registration(
                expectedRegistrationID,
                expectedNewActivationCode,
                expectedNewTokenID,
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        when(tokenUtil.parseRegistrationToken(eq(expectedOldRegistrationToken)))
                .thenReturn(expectedOldTokenClaims);

        when(registrationService.findRegistrationByID(eq(expectedRegistrationID)))
                .thenReturn(Optional.of(expectedRegistration));

        when(activationCodeGenerator.generate())
                .thenReturn(expectedNewActivationCode);

        when(tokenIDGenerator.generate())
                .thenReturn(expectedNewTokenID);

        when(tokenUtil.generateRegistrationToken(eq(expectedNewTokenClaims)))
                .thenReturn(expectedNewRegistrationToken);

        String actualToken = sut.resendEmailVerification(expectedOldRegistrationToken);

        assertEquals(expectedNewRegistrationToken, actualToken);

        verify(registrationService)
                .updateRegistration(eq(expectedUpdatedRegistration));

        verify(emailService)
                .sendRegistrationActivationMessage(eq(expectedEmail), eq(expectedNewActivationCode));
    }

    @Test
    public void Resend_email_verification_with_invalid_registration_token_is_not_successful() {
        String expectedInvalidRegistrationToken = create(String.class);

        when(tokenUtil.parseRegistrationToken(eq(expectedInvalidRegistrationToken)))
                .thenThrow(InvalidTokenException.class);

        assertThrows(
                InvalidRegistrationDataException.class,
                () -> sut.resendEmailVerification(expectedInvalidRegistrationToken)
        );

        verify(registrationService, never())
                .updateRegistration(any());

        verify(emailService, never())
                .sendRegistrationActivationMessage(any(), any());
    }

    @Test
    public void Resend_email_verification_with_invalid_registration_id_is_not_successful() {
        String expectedRegistrationToken = create(String.class);
        String expectedRegistrationID = create(String.class);
        String expectedTokenID = create(String.class);

        RegistrationTokenClaims expectedTokenClaims = new RegistrationTokenClaims(
                expectedTokenID,
                expectedRegistrationID
        );

        when(tokenUtil.parseRegistrationToken(eq(expectedRegistrationToken)))
                .thenReturn(expectedTokenClaims);

        when(registrationService.findRegistrationByID(eq(expectedRegistrationID)))
                .thenReturn(Optional.empty());

        assertThrows(
                InvalidRegistrationDataException.class,
                () -> sut.resendEmailVerification(expectedRegistrationToken)
        );

        verify(registrationService, never())
                .updateRegistration(any());

        verify(emailService, never())
                .sendRegistrationActivationMessage(any(), any());
    }

    @Test
    public void Resend_email_verification_with_invalid_registration_token_id_is_not_successful() {
        String expectedRegistrationToken = create(String.class);
        String expectedRegistrationID = create(String.class);
        String expectedInvalidTokenID = create(String.class);
        String expectedTokenID = create(String.class);
        String expectedActivationCode = create(String.class);
        String expectedUsername = create(String.class);
        String expectedEmail = create(String.class);
        String expectedPassword = create(String.class);
        String expectedSecretWord = create(String.class);

        RegistrationTokenClaims expectedTokenClaims = new RegistrationTokenClaims(
                expectedInvalidTokenID,
                expectedRegistrationID
        );

        Registration expectedRegistration = new Registration(
                expectedRegistrationID,
                expectedActivationCode,
                expectedTokenID,
                expectedUsername,
                expectedEmail,
                expectedPassword,
                expectedSecretWord
        );

        when(tokenUtil.parseRegistrationToken(eq(expectedRegistrationToken)))
                .thenReturn(expectedTokenClaims);

        when(registrationService.findRegistrationByID(eq(expectedRegistrationID)))
                .thenReturn(Optional.of(expectedRegistration));

        assertThrows(
                InvalidRegistrationDataException.class,
                () -> sut.resendEmailVerification(expectedRegistrationToken)
        );

        verify(accountService, never())
                .createAccount(any());

        verify(emailService, never())
                .sendRegistrationActivationMessage(any(), any());
    }

    @Test
    public void Login_with_valid_data_is_successful() {
        String      expectedUserIdentifier = create(String.class);
        String      expectedUserID = create(String.class);
        String      expectedUsername = create(String.class);
        String      expectedEmail = create(String.class);
        String      expectedRequestedPassword = create(String.class);
        String      expectedEncodedPassword = create(String.class);
        String      expectedSecretWord = create(String.class);
        String      expectedAccessToken = create(String.class);
        String      expectedRefreshToken = create(String.class);
        Instant     expectedCreatedAt = create(Instant.class);
        String      expectedTokenID = create(String.class);
        Set<RolesEnum> expectedRoles = ofSet(RolesEnum.class).create();

        SigninRequestBody request = new SigninRequestBody(expectedUserIdentifier, expectedRequestedPassword);

        Account expectedAccount = new Account(
                expectedUserID,
                expectedUsername,
                expectedEmail,
                expectedEncodedPassword,
                expectedSecretWord,
                expectedRoles
        );

        SessionCreationData expectedSessionCreationData = new SessionCreationData(
                expectedUserID,
                expectedRoles.toArray(RolesEnum[]::new)
        );

        Session expectedSession = new Session(
                String.valueOf(expectedUserID),
                expectedRoles.stream().map(RolesEnum::name).toArray(String[]::new),
                expectedCreatedAt,
                expectedAccessToken,
                expectedRefreshToken,
                expectedTokenID
        );

        when(accountService.findAccountByUsernameOrEmail(eq(expectedUserIdentifier), eq(expectedUserIdentifier)))
                .thenReturn(Optional.of(expectedAccount));

        when(passwordEncoder.matches(eq(expectedRequestedPassword), eq(expectedEncodedPassword)))
                .thenReturn(true);

        when(sessionService.createSession(eq(expectedSessionCreationData)))
                .thenReturn(expectedSession);

        Session actualSession = sut.signin(request);

        assertEquals(expectedSession, actualSession);

        verify(sessionService)
                .createSession(eq(expectedSessionCreationData));
    }

    @Test
    public void Login_with_invalid_user_identifier_is_not_successful() {
        String expectedInvalidUserIdentifier = create(String.class);
        String expectedPassword = create(String.class);
        SigninRequestBody request = new SigninRequestBody(expectedInvalidUserIdentifier, expectedPassword);

        when(accountService.findAccountByUsernameOrEmail(
                        eq(expectedInvalidUserIdentifier),
                        eq(expectedInvalidUserIdentifier)))
                .thenReturn(Optional.empty());

        assertThrows(InvalidAccountDataException.class, () -> sut.signin(request));

        verify(sessionService, never())
                .createSession(any());
    }

    @Test
    public void Login_with_invalid_password_is_not_successful() {
        String      expectedUserIdentifier = create(String.class);
        String      expectedUserID = create(String.class);
        String      expectedUsername = create(String.class);
        String      expectedEmail = create(String.class);
        String      expectedRequestedPassword = create(String.class);
        String      expectedEncodedPassword = create(String.class);
        String      expectedSecretWord = create(String.class);
        RolesEnum[] expectedRoles = create(RolesEnum[].class);

        SigninRequestBody request = new SigninRequestBody(expectedUserIdentifier, expectedRequestedPassword);

        Account expectedAccount = new Account(
                expectedUserID,
                expectedUsername,
                expectedEmail,
                expectedEncodedPassword,
                expectedSecretWord,
                Arrays.stream(expectedRoles).collect(Collectors.toSet())
        );

        when(accountService.findAccountByUsernameOrEmail(eq(expectedUserIdentifier), eq(expectedUserIdentifier)))
                .thenReturn(Optional.of(expectedAccount));

        when(passwordEncoder.matches(eq(expectedRequestedPassword), eq(expectedEncodedPassword)))
                .thenReturn(false);

        assertThrows(InvalidAccountDataException.class, () -> sut.signin(request));

        verify(sessionService, never())
                .createSession(any());
    }

    @Test
    public void Logout_with_valid_refresh_token_is_successful() {
        String expectedRefreshToken = create(String.class);

        sut.signout(expectedRefreshToken);

        verify(sessionService)
                .deleteSession(eq(expectedRefreshToken));
    }

    @Test
    public void Logout_with_invalid_refresh_token_is_not_successful() {
        String expectedInvalidRefreshToken = create(String.class);

        doThrow(InvalidTokenException.class)
                .when(sessionService).deleteSession(eq(expectedInvalidRefreshToken));

        assertThrows(InvalidTokenException.class, () -> sut.signout(expectedInvalidRefreshToken));

        verify(sessionService)
                .deleteSession(eq(expectedInvalidRefreshToken));
    }

    @Test
    public void Refreshing_tokens_with_valid_refresh_token_is_successful() {
        String      expectedUserID = create(String.class);
        String      expectedNewAccessToken = create(String.class);
        String      expectedRefreshToken = create(String.class);
        String      expectedNewRefreshToken = create(String.class);
        Instant     expectedNewCreatedAt = create(Instant.class);
        String      expectedNewTokenID = create(String.class);
        Set<RolesEnum> expectedRoles = ofSet(RolesEnum.class).create();

        Session expectedUpdatedSession = new Session(
                String.valueOf(expectedUserID),
                expectedRoles.stream().map(Enum::name).toArray(String[]::new),
                expectedNewCreatedAt,
                expectedNewAccessToken,
                expectedNewRefreshToken,
                expectedNewTokenID
        );

        when(sessionService.refreshSession(eq(expectedRefreshToken)))
                .thenReturn(expectedUpdatedSession);

        Session actualUpdatedSession = sut.refreshTokens(expectedRefreshToken);

        assertEquals(expectedUpdatedSession, actualUpdatedSession);

        verify(sessionService)
                .refreshSession(eq(expectedRefreshToken));
    }

    @Test
    public void Refreshing_tokens_with_invalid_refresh_token_is_not_successful() {
        String expectedInvalidRefreshToken = create(String.class);

        when(sessionService.refreshSession(eq(expectedInvalidRefreshToken)))
                .thenThrow(InvalidTokenException.class);

        assertThrows(InvalidTokenException.class, () -> sut.refreshTokens(expectedInvalidRefreshToken));

        verify(sessionService)
                .refreshSession(eq(expectedInvalidRefreshToken));
    }
}