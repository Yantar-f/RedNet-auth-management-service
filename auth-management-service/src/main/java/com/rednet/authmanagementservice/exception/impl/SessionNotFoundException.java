package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.NotFoundException;

import java.util.List;

public class SessionNotFoundException extends NotFoundException {
    public SessionNotFoundException(String sessionID) {
        super(List.of("session " + sessionID + " not found"));
    }
}
