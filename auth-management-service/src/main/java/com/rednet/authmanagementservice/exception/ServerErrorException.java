package com.rednet.authmanagementservice.exception;

public class ServerErrorException extends RuntimeException {
    public ServerErrorException(String messages) {
        super(messages);
    }
}
