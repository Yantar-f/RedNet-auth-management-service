package com.rednet.authmanagementservice.model;

public record RegistrationCredentials(String registrationID, String registrationToken) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        RegistrationCredentials credentials = (RegistrationCredentials) obj;

        return  registrationID.equals(credentials.registrationID) &&
                registrationToken.equals(credentials.registrationToken);
    }

    @Override
    public int hashCode() {
        return registrationID.hashCode() * registrationToken.hashCode();
    }
}
