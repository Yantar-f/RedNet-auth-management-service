package com.rednet.authmanagementservice.util;

import com.rednet.authmanagementservice.model.RegistrationTokenClaims;
import com.rednet.authmanagementservice.model.SystemTokenClaims;

public interface TokenUtil {
    String generateRegistrationToken(RegistrationTokenClaims claims);

    RegistrationTokenClaims parseRegistrationToken  (String token);
    SystemTokenClaims       parseApiToken           (String token);
}
