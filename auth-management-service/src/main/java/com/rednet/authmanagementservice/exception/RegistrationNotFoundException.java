package com.rednet.authmanagementservice.exception;

public class RegistrationNotFoundException extends RuntimeException {
    public RegistrationNotFoundException(String ID) {
        super("Registration " + ID + "not found");
    }
}
