package com.rednet.authmanagementservice.service;

public interface EmailService {
    void sendRegistrationActivationMessage(String email, String activationCode);
}
