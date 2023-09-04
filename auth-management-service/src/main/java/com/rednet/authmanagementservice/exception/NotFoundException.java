package com.rednet.authmanagementservice.exception;

import java.util.List;

public abstract class NotFoundException extends HandableException{
    public NotFoundException(List<String> messages) {
        super(messages);
    }
}
