package com.rednet.authmanagementservice.exception;

import java.util.List;

public abstract class BadRequestException extends HandableException {
    public BadRequestException(List<String> messages) {
        super(messages);
    }
}
