package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.service.SessionService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SessionServiceImpl implements SessionService {
    @Override
    public Session createSession(String userID, String[] roles) {

        return null;
    }

    @Override
    public List<Session> getSessionsByUserID(String userID) {
        return null;
    }

    @Override
    public Session refreshSession(String refreshToken) {
        return null;
    }

    @Override
    public void deleteSession(String refreshToken) {

    }

    @Override
    public void deleteSessionsByUserID(String userID) {

    }
}
