package com.rednet.authmanagementservice.model;

import com.rednet.authmanagementservice.config.EnumRoles;

import java.util.Set;

public record AccountCreationData(
        String username,
        String email,
        String password,
        String secretWord,
        Set<EnumRoles> roles
) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        AccountCreationData creationData = (AccountCreationData) obj;

        return  username.equals(creationData.username) &&
                email.equals(creationData.email) &&
                password.equals(creationData.password) &&
                secretWord.equals(creationData.secretWord) &&
                roles.size() == creationData.roles.size() &&
                roles.containsAll(creationData.roles);
    }

    @Override
    public int hashCode() {
        return username.hashCode() * email.hashCode() * password.hashCode() * secretWord.hashCode() * roles.hashCode();
    }
}
