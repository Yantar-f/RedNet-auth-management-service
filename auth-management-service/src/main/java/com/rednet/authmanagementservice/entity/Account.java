package com.rednet.authmanagementservice.entity;

import com.rednet.authmanagementservice.config.EnumRoles;
import java.util.Set;

public class Account {
    private String ID;

    private String username;

    private String email;

    private String password;

    private String secretWord;

    private Set<EnumRoles> roles;

    public Account(
            String ID,
            String username,
            String email,
            String password,
            String secretWord,
            Set<EnumRoles> roles
    ) {
        this.ID = ID;
        this.username = username;
        this.password = password;
        this.email = email;
        this.secretWord = secretWord;
        this.roles = roles;
    }

    public String getID() {
        return ID;
    }

    public void setID(String ID) {
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

    public Set<EnumRoles> getRoles() {
        return roles;
    }

    public void setRoles(Set<EnumRoles> roles) {
        this.roles = roles;
    }

    @Override
    public int hashCode() {
        return  ID.hashCode() *
                username.hashCode() *
                email.hashCode() *
                password.hashCode() *
                secretWord.hashCode() *
                roles.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Account account)) return false;

        return  ID.equals(account.ID) &&
                username.equals(account.username) &&
                email.equals(account.email) &&
                password.equals(account.password) &&
                secretWord.equals(account.secretWord) &&
                roles.size() == account.roles.size() &&
                roles.containsAll(account.roles);
    }
}
