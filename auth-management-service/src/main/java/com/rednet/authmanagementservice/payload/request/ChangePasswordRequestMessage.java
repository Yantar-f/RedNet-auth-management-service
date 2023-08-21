package com.rednet.authmanagementservice.payload.request;

import jakarta.validation.constraints.NotBlank;

public record ChangePasswordRequestMessage(
    @NotBlank(message = "user identifier should be not blank")
    String userIdentifier,

    @NotBlank(message = "password should be not blank")
    String oldPassword,

    @NotBlank(message = "password should be not blank")
    String newPassword
) {
}
