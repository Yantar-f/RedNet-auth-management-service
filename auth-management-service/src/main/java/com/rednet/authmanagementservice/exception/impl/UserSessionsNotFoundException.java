package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class UserSessionsNotFoundException extends BadRequestException {
    public UserSessionsNotFoundException(String userID) {
        super(List.of(userID));
    }
}
