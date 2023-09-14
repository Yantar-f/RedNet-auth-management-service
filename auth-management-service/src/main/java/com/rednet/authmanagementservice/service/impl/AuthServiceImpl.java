package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.entity.Role;
import com.rednet.authmanagementservice.dto.SessionDTO;
import com.rednet.authmanagementservice.exception.impl.InvalidRegistrationDataException;
import com.rednet.authmanagementservice.exception.impl.InvalidTokenException;
import com.rednet.authmanagementservice.exception.impl.OccupiedValueException;
import com.rednet.authmanagementservice.exception.impl.InvalidAccountDataException;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerifications;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.repository.AccountRepository;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import com.rednet.authmanagementservice.service.EmailService;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.util.JwtUtil;
import com.rednet.authmanagementservice.util.TokenIDGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

import static com.rednet.authmanagementservice.config.EnumTokenType.REGISTRATION_TOKEN;

@Service
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final RegistrationRepository registrationRepository;
    private final ActivationCodeGenerator activationCodeGenerator;
    private final TokenIDGenerator tokenIDGenerator;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;

    public AuthServiceImpl(
        AccountRepository accountRepository,
        RegistrationRepository registrationRepository,
        ActivationCodeGenerator activationCodeGenerator,
        TokenIDGenerator tokenIDGenerator,
        PasswordEncoder passwordEncoder,
        SessionService sessionService,
        EmailService emailService,
        JwtUtil jwtUtil
    ) {
        this.accountRepository = accountRepository;
        this.registrationRepository = registrationRepository;
        this.activationCodeGenerator = activationCodeGenerator;
        this.tokenIDGenerator = tokenIDGenerator;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.jwtUtil = jwtUtil;
        this.emailService = emailService;
    }

    @Override
    public RegistrationCredentials signup(SignupRequestBody requestMessage) {
        accountRepository.findByUsernameOrEmail(requestMessage.username(), requestMessage.email()).ifPresent(acc -> {
            if (requestMessage.username().equals(acc.getUsername())) {
                throw new OccupiedValueException("Occupied value: username [" + requestMessage.username() + "]");
            } else {
                throw new OccupiedValueException("Occupied value: email [" + requestMessage.email() + "]");
            }
        });

        String
            activationCode = activationCodeGenerator.generate(),
            registrationID = UUID.randomUUID().toString(),
            tokenID = tokenIDGenerator.generate(),
            registrationToken = generateRegistrationToken(registrationID, tokenID);

        registrationRepository.save(registrationID, new Registration(
            activationCode,
            tokenID,
            requestMessage.username(),
            passwordEncoder.encode(requestMessage.password()),
            requestMessage.email(),
            requestMessage.secretWord()
        ));

        emailService.sendRegistrationActivationMessage(requestMessage.email(), activationCode);

        return new RegistrationCredentials(registrationID, registrationToken);
    }

    @Override
    public SessionDTO signin(SigninRequestBody requestMessage) {
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
    public SessionDTO refreshTokens(String refreshToken) {
        return new SessionDTO(sessionService.refreshSession(refreshToken));
    }

    @Override
    public SessionDTO verifyEmail(RegistrationVerifications registrationVerifications) {
        Registration registration = registrationRepository
            .find(registrationVerifications.registrationID())
            .orElseThrow(InvalidRegistrationDataException::new);

        if ( ! registration.getActivationCode().equals(registrationVerifications.activationCode())) {
            throw new InvalidRegistrationDataException();
        }

        registrationRepository.delete(registrationVerifications.registrationID());

        accountRepository.findByUsernameOrEmail(registration.getUsername(), registration.getEmail()).ifPresent(acc -> {
            if (registration.getUsername().equals(acc.getUsername())) {
                throw new OccupiedValueException("Occupied value: username [" + registration.getUsername() + "]");
            } else {
                throw new OccupiedValueException("Occupied value: email [" + registration.getEmail() + "]");
            }
        });

        return createSession(accountRepository.save(new Account(
            registration.getUsername(),
            registration.getPassword(),
            registration.getEmail(),
            registration.getSecretWord(),
            Set.of(new Role(EnumRoles.ROLE_USER))
        )));
    }

    @Override
    public String resendEmailVerification(String registrationToken) {
        try {
            Claims claims = jwtUtil.getRegistrationTokenParser().parseClaimsJws(registrationToken).getBody();
            String registrationID = claims.getSubject();
            String tokenID = claims.getId();

            Registration registration = registrationRepository
                .find(registrationID)
                .orElseThrow(() -> new InvalidTokenException(REGISTRATION_TOKEN));

            if ( ! tokenID.equals(registration.getTokenID())) throw new InvalidTokenException(REGISTRATION_TOKEN);

            String newActivationCode = activationCodeGenerator.generate();
            String newTokenID = tokenIDGenerator.generate();

            registration.setActivationCode(newActivationCode);
            registration.setTokenID(newTokenID);

            registrationRepository.save(registrationID, registration);

            emailService.sendRegistrationActivationMessage(registration.getEmail(), newActivationCode);

            return generateRegistrationToken(registrationID, newTokenID);
        } catch (
            SignatureException |
            MalformedJwtException |
            ExpiredJwtException |
            UnsupportedJwtException |
            IllegalArgumentException e
        ) {
            throw new InvalidTokenException(REGISTRATION_TOKEN);
        }
    }

    private SessionDTO createSession(Account account) {
        return new SessionDTO(sessionService.createSession(
            String.valueOf(account.getID()),
            account.getRoles().stream().map(Role::getDesignation).toArray(String[]::new)
        ));
    }

    private String generateRegistrationToken(String registrationID, String tokenID) {
        return jwtUtil.generateRegistrationTokenBuilder()
            .setSubject(registrationID)
            .setId(tokenID)
            .compact();
    }
}
