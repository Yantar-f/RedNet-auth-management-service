package com.rednet.authmanagementservice.dto;

import com.rednet.authmanagementservice.entity.Session;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class SessionDTO {
    private String      userID;
    private String[]    roles;
    private String      accessToken;
    private String      refreshToken;


    public SessionDTO(Session session) {
        userID = session.getUserID();
        roles = session.getRoles();
        accessToken = session.getAccessToken();
        refreshToken = session.getRefreshToken();
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

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public int hashCode() {
        return userID.hashCode() * Arrays.hashCode(roles) * accessToken.hashCode() * refreshToken.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || this.getClass() != obj.getClass()) return false;

        SessionDTO session = (SessionDTO) obj;

        return  userID.equals(session.userID) &&
                accessToken.equals(session.accessToken) &&
                refreshToken.equals(session.refreshToken) &&
                new HashSet<>(List.of(roles)).containsAll(List.of(session.roles)) &&
                new HashSet<>(List.of(session.roles)).containsAll(List.of(roles));
    }
}
