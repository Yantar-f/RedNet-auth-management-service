package com.rednet.authmanagementservice.exception;

import jakarta.annotation.Nonnull;

import java.util.List;

public class OccupiedValuesException extends RuntimeException {
    private final List<String> messages;
    public OccupiedValuesException(@Nonnull List<String> messages) {
        this.messages = messages;
    }

    public List<String> getMessages() {
        return messages;
    }
}
