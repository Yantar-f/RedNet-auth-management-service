package com.rednet.authmanagementservice.exception;

import com.rednet.authmanagementservice.config.TokenConfig;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(TokenConfig config) {
        super("invalid " + config.getTokenTypeName());
    }
}
