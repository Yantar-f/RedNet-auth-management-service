package com.rednet.authmanagementservice.payload.request;

public record ChangePasswordRequestMessage(String userIdentifier, String oldPassword, String newPassword) {
}
