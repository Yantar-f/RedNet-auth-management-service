package com.rednet.authmanagementservice.util;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;

public interface JwtUtil {
    JwtBuilder  generateRegistrationTokenBuilder();
    JwtParser   getRegistrationTokenParser      ();
    JwtParser   getApiTokenParser               ();
}
