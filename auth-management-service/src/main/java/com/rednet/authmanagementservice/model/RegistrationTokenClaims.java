package com.rednet.authmanagementservice.model;

public class RegistrationTokenClaims {
    private String tokenID;
    private String registrationID;

    public RegistrationTokenClaims(String tokenID, String registrationID) {
        this.tokenID = tokenID;
        this.registrationID = registrationID;
    }

    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    public String getRegistrationID() {
        return registrationID;
    }

    public void setRegistrationID(String registrationID) {
        this.registrationID = registrationID;
    }

    @Override
    public int hashCode() {
        return tokenID.hashCode() * registrationID.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        RegistrationTokenClaims claims = (RegistrationTokenClaims) obj;

        return tokenID.equals(claims.tokenID) && registrationID.equals(claims.registrationID);
    }
}
