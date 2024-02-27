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
import com.rednet.authmanagementservice.model.RegistrationCreationData;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationTokenClaims;
import com.rednet.authmanagementservice.model.RegistrationVerificationData;
import com.rednet.authmanagementservice.model.SessionCreationData;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.service.AccountService;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.service.EmailService;
import com.rednet.authmanagementservice.service.RegistrationService;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.util.TokenIDGenerator;
import com.rednet.authmanagementservice.util.TokenUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountService accountService;
    private final RegistrationService registrationService;
    private final SessionService sessionService;
    private final EmailService emailService;
    private final ActivationCodeGenerator activationCodeGenerator;
    private final TokenIDGenerator tokenIDGenerator;
    private final PasswordEncoder passwordEncoder;
    private final TokenUtil tokenUtil;

    public AuthServiceImpl(AccountService accountService,
                           RegistrationService registrationService,
                           SessionService sessionService,
                           EmailService emailService,
                           ActivationCodeGenerator activationCodeGenerator,
                           TokenIDGenerator tokenIDGenerator,
                           PasswordEncoder passwordEncoder,
                           TokenUtil tokenUtil) {

        this.accountService = accountService;
        this.registrationService = registrationService;
        this.sessionService = sessionService;
        this.emailService = emailService;
        this.activationCodeGenerator = activationCodeGenerator;
        this.tokenIDGenerator = tokenIDGenerator;
        this.passwordEncoder = passwordEncoder;
        this.tokenUtil = tokenUtil;
    }

    @Override
    public RegistrationCredentials register(SignupRequestBody request) {
        AccountUniqueFields fields = new AccountUniqueFields(request.username(), request.email());

        checkAccountUniqueFieldsOccupancy(fields);

        String encodedPassword = encodePassword(request.password());
        String encodedSecretWord = encodeSecretWord(request.secretWord());
        String activationCode = generateActivationCode();
        String tokenID = generateRegistrationTokenID();

        RegistrationCreationData registrationCreationData = new RegistrationCreationData(
                activationCode,
                tokenID,
                request.username(),
                request.email(),
                encodedPassword,
                encodedSecretWord
        );

        Registration registration = createRegistrationFrom(registrationCreationData);

        sendEmailVerification(request.email(), activationCode);

        RegistrationTokenClaims tokenClaims = new RegistrationTokenClaims(tokenID, registration.getID());
        String registrationToken = generateRegistrationTokenFrom(tokenClaims);

        return new RegistrationCredentials(registration.getID(), registrationToken);
    }

    private Registration createRegistrationFrom(RegistrationCreationData registrationCreationData) {
        return registrationService.createRegistration(registrationCreationData);
    }

    private String encodeSecretWord(String secretWord) {
        return passwordEncoder.encode(secretWord);
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private String generateRegistrationTokenID() {
        return tokenIDGenerator.generate();
    }

    private String generateActivationCode() {
        return activationCodeGenerator.generate();
    }

    private String generateRegistrationTokenFrom(RegistrationTokenClaims tokenClaims) {
        return tokenUtil.generateRegistrationToken(tokenClaims);
    }

    private void sendEmailVerification(String email, String activationCode) {
        emailService.sendRegistrationActivationMessage(email, activationCode);
    }

    @Override
    public Session login(SigninRequestBody request) {
        Account account = accountService
                .findAccountByUsernameOrEmail(request.userIdentifier(), request.userIdentifier())
                .orElseThrow(InvalidAccountDataException::new);

        if (! passwordEncoder.matches(request.password(), account.getPassword()))
            throw new InvalidAccountDataException();

        return createSession(account);
    }

    @Override
    public void logout(String refreshToken) {
        sessionService.deleteSession(refreshToken);
    }

    @Override
    public Session refreshSession(String refreshToken) {
        return sessionService.refreshSession(refreshToken);
    }

    @Override
    public Session verifyEmail(RegistrationVerificationData verificationData) {
        Registration registration = registrationService
                .findRegistrationByID(verificationData.registrationID())
                .orElseThrow(InvalidRegistrationDataException::new);

        if (! registration.getActivationCode().equals(verificationData.activationCode()))
            throw new InvalidRegistrationDataException();

        deleteRegistrationByID(registration.getID());

        AccountCreationData creationData = new AccountCreationData(
                registration.getUsername(),
                registration.getEmail(),
                registration.getEncodedPassword(),
                registration.getEncodedSecretWord(),
                new HashSet<>(){{add(RolesEnum.ROLE_USER);}}
        );

        Account account = createAccountFrom(creationData);

        return createSession(account);
    }

    private void deleteRegistrationByID(String id) {
        registrationService.deleteRegistrationByID(id);
    }

    private Account createAccountFrom(AccountCreationData creationData) {
        return accountService.createAccount(creationData);
    }

    @Override
    public String resendEmailVerification(String registrationToken) {
        try {
            RegistrationTokenClaims tokenClaims = parseRegistrationToken(registrationToken);

            Registration registration = registrationService
                    .findRegistrationByID(tokenClaims.getRegistrationID())
                    .orElseThrow(InvalidRegistrationDataException::new);

            if (! tokenClaims.getTokenID().equals(registration.getTokenID()))
                throw new InvalidRegistrationDataException();

            String newActivationCode = generateActivationCode();
            String newTokenID = generateRegistrationTokenID();

            registration.setActivationCode(newActivationCode);
            registration.setTokenID(newTokenID);
            tokenClaims.setTokenID(newTokenID);

            updateRegistration(registration);

            sendEmailVerification(registration.getEmail(), newActivationCode);

            return generateRegistrationTokenFrom(tokenClaims);
        } catch (InvalidTokenException exception) {
            throw new InvalidRegistrationDataException();
        }
    }

    private void updateRegistration(Registration registration) {
        registrationService.updateRegistration(registration);
    }

    private RegistrationTokenClaims parseRegistrationToken(String registrationToken) {
        return tokenUtil.parseRegistrationToken(registrationToken);
    }

    private void checkAccountUniqueFieldsOccupancy(AccountUniqueFields fields) {
        AccountUniqueFieldsOccupancy occupancy = accountService.getAccountUniqueFieldsOccupancy(fields);

        if (occupancy.isAnyOccupied()) {
            HashMap<String, String> occupiedFields = new HashMap<>();

            if (occupancy.isUsernameOccupied())
                occupiedFields.put("username", occupancy.username());

            if (occupancy.isEmailOccupied())
                occupiedFields.put("email", occupancy.email());

            throw new OccupiedValueException(occupiedFields);
        }
    }

    private Session createSession(Account account) {
        SessionCreationData sessionCreationData = new SessionCreationData(
                account.getID(),
                account.getRoles().toArray(RolesEnum[]::new)
        );

        return sessionService.createSession(sessionCreationData);
    }
}
