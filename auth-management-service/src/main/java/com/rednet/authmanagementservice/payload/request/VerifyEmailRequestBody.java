package com.rednet.authmanagementservice.payload.request;

import jakarta.validation.constraints.NotBlank;

public record VerifyEmailRequestBody(
    @NotBlank(message = "registration id should be not blank")
    String registrationID,

    @NotBlank(message = "activation code should be not blank")
    String activationCode
) {
}