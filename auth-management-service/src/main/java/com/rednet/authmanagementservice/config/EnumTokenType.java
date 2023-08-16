package com.rednet.authmanagementservice.config;

public enum EnumTokenType {
    REFRESH_TOKEN("refresh token"),
    ACCESS_TOKEN("access token"),
    REGISTRATION_TOKEN("registration token");

    private final String name;
    EnumTokenType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
