package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class MissingTokenException extends BadRequestException {
    public MissingTokenException(String message) {
        super(List.of(message));
    }
}
