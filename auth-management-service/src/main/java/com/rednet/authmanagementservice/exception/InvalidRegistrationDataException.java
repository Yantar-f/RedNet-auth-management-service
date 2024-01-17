package com.rednet.authmanagementservice.exception;

public class InvalidRegistrationDataException extends RuntimeException {
    public InvalidRegistrationDataException() {
        super("Invalid registration data");
    }
}
