package com.rednet.authmanagementservice.payload.request;

import jakarta.validation.constraints.NotEmpty;

public record SigninRequestBody(
    @NotEmpty(message = "user identifier should be not blank")
    String userIdentifier,

    @NotEmpty(message = "encodedPassword should be not blank")
    String password
) {
    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        SigninRequestBody body = (SigninRequestBody) obj;

        return  userIdentifier.equals(body.userIdentifier) &&
                password.equals(body.password);
    }

    @Override
    public int hashCode() {
        return userIdentifier.hashCode() * password.hashCode();
    }
}
