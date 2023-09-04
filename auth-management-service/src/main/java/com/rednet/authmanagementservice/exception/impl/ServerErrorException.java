package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.HandableException;
import jakarta.annotation.Nonnull;

import java.util.List;

public class ServerErrorException extends HandableException {
    public ServerErrorException(@Nonnull String messages) {
        super(List.of(messages));
    }
}
