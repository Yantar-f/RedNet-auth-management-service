package com.rednet.authmanagementservice.model;

import com.rednet.authmanagementservice.entity.Session;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class SessionDTO {
    private String userID;
    private String[] roles;

    public SessionDTO() {}

    public SessionDTO(Session session) {
        userID = session.getUserID();
        roles = session.getRoles();
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String[] getRoles() {
        return roles;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }

    @Override
    public int hashCode() {
        return userID.hashCode() * Arrays.hashCode(roles);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || this.getClass() != obj.getClass()) return false;

        SessionDTO session = (SessionDTO) obj;

        return  userID.equals(session.userID) &&
                new HashSet<>(List.of(roles)).containsAll(List.of(session.roles)) &&
                new HashSet<>(List.of(session.roles)).containsAll(List.of(roles));
    }
}
