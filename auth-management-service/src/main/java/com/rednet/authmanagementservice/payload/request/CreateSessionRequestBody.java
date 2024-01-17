package com.rednet.authmanagementservice.payload.request;

import com.rednet.authmanagementservice.config.EnumRoles;

public record CreateSessionRequestBody(String userID, EnumRoles[] roles) {
}
