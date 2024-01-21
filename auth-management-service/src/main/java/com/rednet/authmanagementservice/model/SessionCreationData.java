package com.rednet.authmanagementservice.model;

import com.rednet.authmanagementservice.config.RolesEnum;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public record SessionCreationData(String userID, RolesEnum[] roles) {
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        SessionCreationData creationData = (SessionCreationData) obj;

        return  userID.equals(creationData.userID) &&
                roles.length == creationData.roles.length &&
                new HashSet<>(List.of(roles)).containsAll(List.of(creationData.roles)) &&
                new HashSet<>(List.of(creationData.roles)).containsAll(List.of(roles));
    }

    @Override
    public int hashCode() {
        return userID.hashCode() * Arrays.hashCode(roles);
    }
}
