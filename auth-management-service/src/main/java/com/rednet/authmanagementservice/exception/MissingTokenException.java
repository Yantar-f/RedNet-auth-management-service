package com.rednet.authmanagementservice.exception;

import com.rednet.authmanagementservice.config.EnumTokenType;

public class MissingTokenException extends RuntimeException {
    public MissingTokenException(EnumTokenType tokenType) {
        super("Missing " + tokenType.getName());
    }
}
