package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.config.RolesEnum;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.model.SessionCreationData;

public interface SessionService {
    Session createSession   (SessionCreationData creationData);
    Session refreshSession  (String refreshToken);
    void    deleteSession   (String refreshToken);
}
