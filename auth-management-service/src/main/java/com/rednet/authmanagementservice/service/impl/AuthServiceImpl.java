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
    public RegistrationCredentials signup(SignupRequestBody request) {
        AccountUniqueFields fields = new AccountUniqueFields(request.username(), request.email());
        AccountUniqueFieldsOccupancy occupancy = accountService.checkAccountUniqueFieldsOccupancy(fields);

        if (occupancy.isAnyOccupied()) {
            HashMap<String, String> occupiedFields = new HashMap<>();

            if (occupancy.isUsernameOccupied())
                occupiedFields.put("username", occupancy.username());

            if (occupancy.isEmailOccupied())
                occupiedFields.put("email", occupancy.email());

            throw new OccupiedValueException(occupiedFields);
        }

        String activationCode = activationCodeGenerator.generate();
        String encodedPassword = passwordEncoder.encode(request.password());
        String encodedSecretWord = passwordEncoder.encode(request.secretWord());
        String tokenID = tokenIDGenerator.generate();

        Registration registration = registrationService.createRegistration(new RegistrationCreationData(
                activationCode,
                tokenID,
                request.username(),
                request.email(),
                encodedPassword,
                encodedSecretWord
        ));

        emailService.sendRegistrationActivationMessage(request.email(), activationCode);

        RegistrationTokenClaims tokenClaims = new RegistrationTokenClaims(tokenID, registration.getID());
        String registrationToken = tokenUtil.generateRegistrationToken(tokenClaims);

        return new RegistrationCredentials(registration.getID(), registrationToken);
    }

    @Override
    public Session signin(SigninRequestBody request) {
        Account account = accountService
                .findAccountByUsernameOrEmail(request.userIdentifier(), request.userIdentifier())
                .orElseThrow(InvalidAccountDataException::new);

        if (! passwordEncoder.matches(request.password(), account.getPassword()))
            throw new InvalidAccountDataException();

        return createSession(account);
    }

    @Override
    public void signout(String refreshToken) {
        sessionService.deleteSession(refreshToken);
    }

    @Override
    public Session refreshTokens(String refreshToken) {
        return sessionService.refreshSession(refreshToken);
    }

    @Override
    public Session verifyEmail(RegistrationVerificationData verificationData) {
        Registration registration = registrationService
                .findRegistrationByID(verificationData.registrationID())
                .orElseThrow(InvalidRegistrationDataException::new);

        if (! registration.getActivationCode().equals(verificationData.activationCode()))
            throw new InvalidRegistrationDataException();

        registrationService.deleteRegistrationByID(registration.getID());

        AccountCreationData creationData = new AccountCreationData(
                registration.getUsername(),
                registration.getEmail(),
                registration.getEncodedPassword(),
                registration.getEncodedSecretWord(),
                new HashSet<>(){{add(RolesEnum.ROLE_USER);}}
        );

        Account account = accountService.createAccount(creationData);

        return createSession(account);
    }


    @Override
    public String resendEmailVerification(String registrationToken) {
        try {
            RegistrationTokenClaims tokenClaims = tokenUtil.parseRegistrationToken(registrationToken);

            Registration registration = registrationService
                    .findRegistrationByID(tokenClaims.getRegistrationID())
                    .orElseThrow(InvalidRegistrationDataException::new);

            if (! tokenClaims.getTokenID().equals(registration.getTokenID()))
                throw new InvalidRegistrationDataException();

            String newActivationCode = activationCodeGenerator.generate();
            String newTokenID = tokenIDGenerator.generate();

            registration.setActivationCode(newActivationCode);
            registration.setTokenID(newTokenID);

            tokenClaims.setTokenID(newTokenID);

            registrationService.updateRegistration(registration);

            emailService.sendRegistrationActivationMessage(registration.getEmail(), newActivationCode);

            return tokenUtil.generateRegistrationToken(tokenClaims);
        } catch (InvalidTokenException exception) {
            throw new InvalidRegistrationDataException();
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
