package com.rednet.authmanagementservice.exception;

public class OccupiedValueException extends RuntimeException {
    public OccupiedValueException(String message) {
        super(message);
    }
}
