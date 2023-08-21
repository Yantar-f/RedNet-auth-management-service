package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.entity.Session;

import java.util.List;

public interface SessionService {
    Session createSession(String userID, String[] roles);
    List<Session> getSessionsByUserID(String userID);
    Session refreshSession(String refreshToken);
    void deleteSession(String refreshToken);
    void deleteSessionsByUserID(String userID);
}
