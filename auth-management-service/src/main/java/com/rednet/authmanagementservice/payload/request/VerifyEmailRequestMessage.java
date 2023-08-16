package com.rednet.authmanagementservice.payload.request;

public record VerifyEmailRequestMessage(String registrationID, String activationCode) {
}