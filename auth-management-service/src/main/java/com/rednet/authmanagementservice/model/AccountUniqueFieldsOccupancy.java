
package com.rednet.authmanagementservice.model;
public record AccountUniqueFieldsOccupancy(
        String username,
        String email,
        boolean isUsernameOccupied,
        boolean isEmailOccupied
) {
    public boolean isAnyOccupied() {
        return  isUsernameOccupied || isEmailOccupied;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        AccountUniqueFieldsOccupancy fields = (AccountUniqueFieldsOccupancy) obj;

        return  username.equals(fields.username) &&
                email.equals(fields.email) &&
                isUsernameOccupied == fields.isUsernameOccupied &&
                isEmailOccupied == fields.isEmailOccupied;
    }

    @Override
    public int hashCode() {
        return  username.hashCode() *
                email.hashCode() *
                Boolean.hashCode(isUsernameOccupied) *
                Boolean.hashCode(isEmailOccupied);
    }
}
