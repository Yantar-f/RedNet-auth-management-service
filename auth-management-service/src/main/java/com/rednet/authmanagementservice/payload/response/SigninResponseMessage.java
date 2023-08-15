package com.rednet.authmanagementservice.payload.response;

import com.rednet.authmanagementservice.config.EnumRoles;

import java.util.Set;

public record SigninResponseMessage(long id, Set<EnumRoles> roles) {
}
