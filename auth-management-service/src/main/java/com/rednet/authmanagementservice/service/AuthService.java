package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.dto.SessionDTO;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerifications;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;

public interface AuthService {
    RegistrationCredentials signup          (SignupRequestBody requestMessage);

    SessionDTO              signin          (SigninRequestBody requestMessage);

    void                    signout         (String refreshToken);

    SessionDTO              refreshTokens   (String refreshToken);


    String      resendEmailVerification (String registrationToken);

    SessionDTO  verifyEmail             (RegistrationVerifications registrationVerifications);
}
