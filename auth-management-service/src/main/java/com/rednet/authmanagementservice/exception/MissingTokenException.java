package com.rednet.authmanagementservice.exception;

import com.rednet.authmanagementservice.config.TokenConfig;

public class MissingTokenException extends RuntimeException {
    public MissingTokenException(TokenConfig config) {
        super("Missing " + config.getTokenTypeName());
    }
}
