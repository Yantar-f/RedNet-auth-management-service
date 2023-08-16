package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.config.EnumTokenType;
import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class InvalidTokenException extends BadRequestException {
    public InvalidTokenException(EnumTokenType tokenType) {
        super(List.of("invalid " + tokenType.getName()));
    }
}
