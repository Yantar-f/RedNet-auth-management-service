package com.rednet.authmanagementservice.model;

import com.rednet.authmanagementservice.config.EnumRoles;

import java.util.HashSet;
import java.util.List;

public class SystemTokenClaims {
    String subjectID;
    String sessionID;
    String tokenID;
    List<EnumRoles> roles;

    public SystemTokenClaims(
            String subjectID,
            String sessionID,
            String tokenID,
            List<EnumRoles> roles
    ) {
        this.subjectID = subjectID;
        this.sessionID = sessionID;
        this.tokenID = tokenID;
        this.roles = roles;
    }

    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public String getSessionID() {
        return sessionID;
    }

    public void setSessionID(String sessionID) {
        this.sessionID = sessionID;
    }

    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    public List<EnumRoles> getRoles() {
        return roles;
    }

    public void setRoles(List<EnumRoles> roles) {
        this.roles = roles;
    }

    @Override
    public int hashCode() {
        return subjectID.hashCode() * sessionID.hashCode() * tokenID.hashCode() * roles.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        SystemTokenClaims tokenClaims = (SystemTokenClaims) obj;

        return  subjectID.equals(tokenClaims.subjectID) &&
                sessionID.equals(tokenClaims.sessionID) &&
                tokenID.equals(tokenClaims.tokenID) &&
                roles.size() == tokenClaims.roles.size() &&
                new HashSet<>(roles).containsAll(tokenClaims.roles);
    }
}
