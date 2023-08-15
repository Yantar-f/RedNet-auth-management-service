package com.rednet.authmanagementservice.payload.request;

public class VerifyEmailRequestMessage {
    private final String registrationID;
    private final String activationCode;

    public VerifyEmailRequestMessage(String registrationID, String activationCode) {
        this.registrationID = registrationID;
        this.activationCode = activationCode;
    }

    public String getRegistrationID() {
        return registrationID;
    }

    public String getActivationCode() {
        return activationCode;
    }
}