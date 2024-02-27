package com.rednet.authmanagementservice.model;

import jakarta.validation.constraints.NotBlank;

public record RegistrationVerificationData(
    @NotBlank(message = "registration id should be not blank")
    String registrationID,

    @NotBlank(message = "activation code should be not blank")
    String activationCode
) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        RegistrationVerificationData data = (RegistrationVerificationData) obj;

        return  registrationID.equals(data.registrationID) &&
                activationCode.equals(data.activationCode);
    }

    @Override
    public int hashCode() {
        return registrationID.hashCode() * activationCode.hashCode();
    }
}
