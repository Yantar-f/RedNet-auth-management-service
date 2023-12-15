package com.rednet.authmanagementservice.payload.request;

public record CreateSessionRequestBody(String userID, String[] roles) {
}
