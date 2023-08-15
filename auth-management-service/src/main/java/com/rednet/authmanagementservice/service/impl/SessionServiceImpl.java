package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.service.SessionService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SessionServiceImpl implements SessionService {
    @Override
    public String createSession(String userID) {
        return null;
    }

    @Override
    public List<String> getSessionsByUserID(String userID) {
        return null;
    }

    @Override
    public void refreshSession(String sessionID) {

    }

    @Override
    public void deleteSession(String sessionID) {

    }

    @Override
    public void deleteSessionsByUserID(String userID) {

    }
}
