package com.rednet.authmanagementservice.entity;

public class Session {
    private String sessionID;
    private String accessToken;
    private String refreshToken;

    public Session(String sessionID, String accessToken, String refreshToken) {
        this.sessionID = sessionID;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getSessionID() {
        return sessionID;
    }

    public void setSessionID(String sessionID) {
        this.sessionID = sessionID;
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
