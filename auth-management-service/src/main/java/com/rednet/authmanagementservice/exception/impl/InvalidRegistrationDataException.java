package com.rednet.authmanagementservice.exception.impl;

public class InvalidRegistrationDataException extends RuntimeException {
    public InvalidRegistrationDataException() {
        super("Invalid registration data");
    }
}
