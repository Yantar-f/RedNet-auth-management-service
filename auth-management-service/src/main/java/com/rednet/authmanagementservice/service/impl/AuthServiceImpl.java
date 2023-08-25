package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.entity.Role;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.impl.InvalidRegistrationActivationCodeException;
import com.rednet.authmanagementservice.exception.impl.OccupiedValuesException;
import com.rednet.authmanagementservice.exception.impl.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.impl.RegistrationNotFoundException;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerifications;
import com.rednet.authmanagementservice.model.ChangePasswordCredentials;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.payload.response.SimpleResponseBody;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import com.rednet.authmanagementservice.service.EmailService;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final RegistrationRepository registrationRepository;
    private final ActivationCodeGenerator activationCodeGenerator;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;
    private final long registrationTokenActivationMs;
    private final long registrationExpirationMs;

    public AuthServiceImpl(
        AccountRepository accountRepository,
        RegistrationRepository registrationRepository,
        ActivationCodeGenerator activationCodeGenerator,
        PasswordEncoder passwordEncoder,
        SessionService sessionService,
        EmailService emailService,
        JwtUtil jwtUtil,
        @Value("${rednet.app.registration-token-activation-ms}") long registrationTokenActivationMs,
        @Value("${rednet.app.registration-token-expiration-ms}") long registrationExpirationMs
    ) {
        this.accountRepository = accountRepository;
        this.registrationRepository = registrationRepository;
        this.activationCodeGenerator = activationCodeGenerator;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.jwtUtil = jwtUtil;
        this.registrationTokenActivationMs = registrationTokenActivationMs;
        this.registrationExpirationMs = registrationExpirationMs;
        this.emailService = emailService;
    }


    @Override
    public RegistrationCredentials signup(SignupRequestBody requestMessage) {
        accountRepository.findByUsernameOrEmail(requestMessage.username(), requestMessage.email()).ifPresent(acc -> {
            throw new OccupiedValuesException(new ArrayList<>(){{
                if (requestMessage.username().equals(acc.getUsername())) add("Occupied value: username");
                if (requestMessage.email().equals(acc.getEmail())) add("Occupied value: email");
            }});
        });

        String
            activationCode = String.valueOf(activationCodeGenerator.generate()),
            registrationID = UUID.randomUUID().toString(),
            registrationToken = generateRegistrationToken(registrationID);

        registrationRepository.save(registrationID, new Registration(
            activationCode,
            requestMessage.username(),
            passwordEncoder.encode(requestMessage.password()),
            requestMessage.email(),
            requestMessage.secretWord()
        ));

        emailService.sendRegistrationActivationMessage(requestMessage.email(), activationCode);

        return new RegistrationCredentials(registrationID, registrationToken);
    }

    @Override
    public Session signin(SigninRequestBody requestMessage) {
        Account account = accountRepository
            .findEagerByUsernameOrEmail(requestMessage.userIdentifier(), requestMessage.userIdentifier())
            .orElseThrow(InvalidAccountDataException::new);

        if (!passwordEncoder.matches(requestMessage.password(), account.getPassword())) {
            throw new InvalidAccountDataException();
        }

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
    public Session verifyEmail(RegistrationVerifications registrationVerifications) {
        Registration registration = registrationRepository
            .find(registrationVerifications.registrationID())
            .orElseThrow(() -> new RegistrationNotFoundException(registrationVerifications.registrationID()));

        if ( ! registration.getActivationCode().equals(registrationVerifications.activationCode())) {
            throw new InvalidRegistrationActivationCodeException(registrationVerifications.activationCode());
        }

        registrationRepository.delete(registrationVerifications.registrationID());

        accountRepository.findByUsernameOrEmail(registration.getUsername(), registration.getEmail()).ifPresent(acc -> {
            throw new OccupiedValuesException(new ArrayList<>(){{
                if (registration.getUsername().equals(acc.getUsername())) add("Occupied value: username");
                if (registration.getEmail().equals(acc.getEmail())) add("Occupied value: email");
            }});
        });

        return createSession(accountRepository.save(new Account(
            registration.getUsername(),
            registration.getPassword(),
            registration.getEmail(),
            registration.getSecretWord(),
            new HashSet<>(){{add(new Role(EnumRoles.ROLE_USER));}}
        )));
    }

    @Override
    public String resendEmailVerification(String registrationToken) {
        String registrationID = jwtUtil.getRegistrationTokenParser().parseClaimsJws(registrationToken)
            .getBody().getSubject();
        Registration registration = registrationRepository
            .find(registrationID)
            .orElseThrow(() -> new RegistrationNotFoundException(registrationID));
        String newActivationCode = String.valueOf(activationCodeGenerator.generate());

        registration.setActivationCode(newActivationCode);

        registrationRepository.save(registrationID, registration);

        emailService.sendRegistrationActivationMessage(registration.getEmail(), newActivationCode);

        return generateRegistrationToken(registrationID);
    }

    @Override
    public void changePassword(ChangePasswordCredentials requestMessage) {
        Account account = accountRepository
            .findByUsernameOrEmail(requestMessage.userIdentifier(), requestMessage.userIdentifier())
            .orElseThrow(InvalidAccountDataException::new);

        if (!passwordEncoder.matches(requestMessage.oldPassword(), account.getPassword())) {
            throw new InvalidAccountDataException();
        }

        account.setPassword(passwordEncoder.encode(requestMessage.newPassword()));

        accountRepository.save(account);
    }

    private Session createSession(Account account) {
        return sessionService.createSession(
            String.valueOf(account.getID()),
            (String[]) account.getRoles().stream().map(Role::getDesignation).toArray());
    }

    private String generateRegistrationToken(String registrationID) {
        return jwtUtil.generateRegistrationTokenBuilder()
            .setSubject(registrationID)
            .setNotBefore(new Date(System.currentTimeMillis() + registrationTokenActivationMs))
            .setExpiration(new Date(System.currentTimeMillis() + registrationExpirationMs))
            .compact();
    }
}
