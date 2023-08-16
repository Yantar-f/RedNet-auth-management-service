package com.rednet.authmanagementservice.payload.request;

public record SignupRequestMessage(String username, String email, String password, String secretWord) {
}
