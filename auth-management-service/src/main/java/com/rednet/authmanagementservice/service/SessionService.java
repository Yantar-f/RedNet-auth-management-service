package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.entity.Session;

public interface SessionService {
    Session createSession   (String userID, EnumRoles[] roles);
    Session refreshSession  (String refreshToken);
    void    deleteSession   (String refreshToken);
}
