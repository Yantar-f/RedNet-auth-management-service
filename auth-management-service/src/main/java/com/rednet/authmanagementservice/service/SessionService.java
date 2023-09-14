package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.entity.Session;

public interface SessionService {
    Session createSession(String userID, String[] roles);
    Session refreshSession(String refreshToken);
    void deleteSession(String refreshToken);
}
