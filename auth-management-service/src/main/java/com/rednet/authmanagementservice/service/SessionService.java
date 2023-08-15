package com.rednet.authmanagementservice.service;

import java.util.List;

public interface SessionService {
    String createSession(String userID);
    List<String> getSessionsByUserID(String userID);
    void refreshSession(String sessionID);
    void deleteSession(String sessionID);
    void deleteSessionsByUserID(String userID);
}
