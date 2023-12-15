package com.rednet.authmanagementservice.exception.impl;

public class OccupiedValueException extends RuntimeException {
    public OccupiedValueException(String messages) {
        super(messages);
    }
}
