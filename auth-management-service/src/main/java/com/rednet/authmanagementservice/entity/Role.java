package com.rednet.authmanagementservice.entity;

import com.rednet.authmanagementservice.config.EnumRoles;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "roles")
public class Role {
    @Id
    @Column(name = "designation")
    private String designation;

    protected Role() {}
    public Role(EnumRoles role){
        this.designation = role.name();
    }

    public String getDesignation() {
        return designation;
    }

    public void setDesignation(EnumRoles role) {
        this.designation = role.name();
    }

}
