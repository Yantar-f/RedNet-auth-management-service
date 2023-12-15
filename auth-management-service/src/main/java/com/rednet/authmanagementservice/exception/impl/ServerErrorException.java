package com.rednet.authmanagementservice.exception.impl;

public class ServerErrorException extends RuntimeException {
    public ServerErrorException(String messages) {
        super(messages);
    }
}
