package com.rednet.authmanagementservice.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.Length;

public record SignupRequestBody(
    @NotBlank(message = "username should be not blank")
    String username,

    @Email(message = "invalid email")
    @NotBlank(message = "email should be not blank")
    String email,

    @Length(min = 8, max = 200, message = "password length should be between 8 and 200")
    String password,

    @Length(min = 8, max = 100, message = "secret word length should be between 8 and 100")
    String secretWord
) {
}
