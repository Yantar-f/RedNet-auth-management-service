package com.rednet.authmanagementservice.dto;

import com.rednet.authmanagementservice.entity.Session;

public class SessionDTO {
    private String userID;
    private String[] roles;
    private String accessToken;
    private String refreshToken;


    public SessionDTO(Session session) {
        userID = session.getUserID();
        roles = session.getRoles();
        accessToken = session.getAccessToken();
        refreshToken = session.getRefreshToken();
    }

    public SessionDTO(String userID, String[] roles, String accessToken, String refreshToken) {
        this.userID = userID;
        this.roles = roles;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
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
}
