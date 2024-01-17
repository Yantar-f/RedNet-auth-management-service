package com.rednet.authmanagementservice.model;

public record AccountUniqueFields(String username, String email) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        AccountUniqueFields fields = (AccountUniqueFields) obj;

        return username.equals(fields.username) && email.equals(fields.email);
    }

    @Override
    public int hashCode() {
        return username.hashCode() * email.hashCode();
    }
}
