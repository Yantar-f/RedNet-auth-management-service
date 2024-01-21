package com.rednet.authmanagementservice.payload.request;

public record RefreshSessionRequestBody(String refreshToken) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        RefreshSessionRequestBody requestBody = (RefreshSessionRequestBody) obj;

        return refreshToken.equals(requestBody.refreshToken);
    }

    @Override
    public int hashCode() {
        return refreshToken.hashCode();
    }
}
