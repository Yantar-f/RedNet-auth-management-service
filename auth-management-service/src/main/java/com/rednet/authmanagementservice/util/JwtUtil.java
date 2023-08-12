package com.rednet.authmanagementservice.util;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;

public interface JwtUtil {
    JwtBuilder generateAccessTokenBuilder();
    JwtBuilder generateRefreshTokenBuilder();
    JwtBuilder generateRegistrationTokenBuilder();
    JwtParser getAccessTokenParser();
    JwtParser getRefreshTokenParser();
    JwtParser getRegistrationTokenParser();
}
