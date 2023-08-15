package com.rednet.authmanagementservice.entity;

import com.rednet.authmanagementservice.config.EnumRoles;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.util.Set;

@Table(name = "accounts")
public class Account {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long ID;

    @Column(name = "username")
    private String username;

    @Column(name = "email")
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "secret_word")
    private String secretWord;

    @Column(name = "is_activated")
    private boolean isActivated = false;

    @ManyToMany(
        fetch = FetchType.EAGER,
        cascade = CascadeType.MERGE)
    @JoinTable(
        name = "accounts_to_roles",
        joinColumns = @JoinColumn (name = "account_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<EnumRoles> roles;

    public Account(
        String username,
        String password,
        String email,
        String secretWord,
        Set<EnumRoles> roles) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.secretWord = secretWord;
        this.roles = roles;
    }

    public long getID() {
        return ID;
    }

    public void setID(long ID) {
        this.ID = ID;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSecretWord() {
        return secretWord;
    }

    public void setSecretWord(String secretWord) {
        this.secretWord = secretWord;
    }

    public boolean isActivated() {
        return isActivated;
    }

    public void setActivated(boolean activated) {
        isActivated = activated;
    }

    public Set<EnumRoles> getRoles() {
        return roles;
    }

    public void setRoles(Set<EnumRoles> roles) {
        this.roles = roles;
    }
}
