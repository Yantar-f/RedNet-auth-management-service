package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class RegistrationNotFoundException extends BadRequestException {
    public RegistrationNotFoundException(String registrationID) {
        super(List.of("Registration " + registrationID + " not found"));
    }
}
