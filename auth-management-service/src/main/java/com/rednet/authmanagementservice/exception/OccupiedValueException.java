package com.rednet.authmanagementservice.exception;

import java.util.Map;

public class OccupiedValueException extends RuntimeException {
    public OccupiedValueException(Map<String, String> occupiedFields) {
        super("Occupied values: " + occupiedFields);
    }
}
