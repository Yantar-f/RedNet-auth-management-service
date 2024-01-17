package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerificationData;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;

public interface AuthService {
    RegistrationCredentials signup          (SignupRequestBody requestMessage);
    Session                 signin          (SigninRequestBody requestMessage);
    void                    signout         (String refreshToken);
    Session                 refreshTokens   (String refreshToken);

    String      resendEmailVerification (String registrationToken);
    Session     verifyEmail             (RegistrationVerificationData registrationVerificationData);
}
