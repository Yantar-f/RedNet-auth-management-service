package com.rednet.authmanagementservice.exception;

public class InvalidRegistrationActivationCodeException extends RuntimeException {
    public InvalidRegistrationActivationCodeException(String activationCode) {
        super("Invalid registration activation code: " + activationCode);
    }
}
