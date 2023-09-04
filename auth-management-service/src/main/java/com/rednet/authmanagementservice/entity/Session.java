package com.rednet.authmanagementservice.entity;

import java.util.Date;

public class Session {
    private String userID;
    private String[] roles;
    private Date createdAt;
    private String accessToken;
    private String refreshToken;
    private String tokenID;

    public Session(
        String userID,
        String[] roles,
        Date createdAt,
        String accessToken,
        String refreshToken,
        String tokenID
    ) {
        this.userID = userID;
        this.roles = roles;
        this.createdAt = createdAt;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenID = tokenID;
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

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }
}
