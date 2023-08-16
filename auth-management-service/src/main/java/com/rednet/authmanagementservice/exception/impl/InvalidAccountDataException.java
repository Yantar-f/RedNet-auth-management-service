package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class InvalidAccountDataException extends BadRequestException {
    public InvalidAccountDataException() {
        super(List.of("Invalid account data exception"));
    }
}
