package com.rednet.authmanagementservice.model;

public record RegistrationData(
        String activationCode,
        String tokenID,
        String username,
        String email,
        String encodedPassword,
        String encodedSecretWord
) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        RegistrationData data = (RegistrationData) obj;

        return  activationCode.equals(data.activationCode) &&
                tokenID.equals(data.tokenID) &&
                username.equals(data.username) &&
                email.equals(data.email) &&
                encodedPassword.equals(data.encodedPassword) &&
                encodedSecretWord.equals(data.encodedSecretWord);
    }

    @Override
    public int hashCode() {
        return  activationCode.hashCode() *
                tokenID.hashCode() *
                username.hashCode() *
                email.hashCode() *
                encodedPassword.hashCode() *
                encodedSecretWord.hashCode();
    }
}
