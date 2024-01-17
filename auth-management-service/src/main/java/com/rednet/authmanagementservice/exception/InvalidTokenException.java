package com.rednet.authmanagementservice.exception;

import com.rednet.authmanagementservice.config.EnumTokenType;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(EnumTokenType tokenType) {
        super("invalid " + tokenType.getName());
    }
}
