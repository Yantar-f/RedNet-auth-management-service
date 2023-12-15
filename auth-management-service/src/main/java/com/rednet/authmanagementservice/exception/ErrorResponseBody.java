package com.rednet.authmanagementservice.exception;

import java.time.Instant;

public record ErrorResponseBody(String status, Instant timestamp, String path, String message){
}

