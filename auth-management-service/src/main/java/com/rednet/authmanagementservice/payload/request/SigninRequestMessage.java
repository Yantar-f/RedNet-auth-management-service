package com.rednet.authmanagementservice.payload.request;

import jakarta.validation.constraints.NotBlank;

public record SigninRequestMessage(
    @NotBlank(message = "user identifier should be not blank")
    String userIdentifier,

    @NotBlank(message = "password should be not blank")
    String password
) {
}
