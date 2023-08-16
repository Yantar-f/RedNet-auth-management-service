package com.rednet.authmanagementservice.exception.impl;

import com.rednet.authmanagementservice.exception.BadRequestException;

import java.util.List;

public class OccupiedValuesException extends BadRequestException {
    public OccupiedValuesException(List<String> messages) {
        super(messages);
    }
}
