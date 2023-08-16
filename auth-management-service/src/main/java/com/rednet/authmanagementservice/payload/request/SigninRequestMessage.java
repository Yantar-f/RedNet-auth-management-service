package com.rednet.authmanagementservice.payload.request;

public record SigninRequestMessage(String userIdentifier, String password) {
}
