package com.rednet.authmanagementservice.model;

import jakarta.validation.constraints.NotBlank;

public record RegistrationVerifications(
    @NotBlank(message = "registration id should be not blank")
    String registrationID,

    @NotBlank(message = "activation code should be not blank")
    String activationCode
) {
}
