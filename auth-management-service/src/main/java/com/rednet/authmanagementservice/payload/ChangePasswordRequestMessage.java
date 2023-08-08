package com.rednet.authmanagementservice.payload;

public class ChangePasswordRequestMessage {
    String userIdentifier;
    String oldPassword;
    String newPassword;

    public String getUserIdentifier() {
        return userIdentifier;
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }
}
