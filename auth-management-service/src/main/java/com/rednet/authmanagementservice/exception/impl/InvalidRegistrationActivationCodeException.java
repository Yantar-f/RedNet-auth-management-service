package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class InvalidRegistrationActivationCodeException extends BadRequestException {
    public InvalidRegistrationActivationCodeException(String activationCode) {
        super(List.of("Invalid registration activation code: " + activationCode));
    }
}
