package com.rednet.authmanagementservice.payload;

public class SigninRequestMessage {
    private String userIdentifier;
    private String password;

    public String getUserIdentifier() {
        return userIdentifier;
    }

    public String getPassword() {
        return password;
    }
}
