package com.rednet.authmanagementservice.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.util.Set;

@Entity
@Table(
    name = "accounts",

    uniqueConstraints = {
        @UniqueConstraint(name = "unique_username_constraint", columnNames = "username"),
        @UniqueConstraint(name = "unique_email_constraint", columnNames = "email")
    },

    indexes = {
        @Index(name = "username_index", columnList = "username"),
        @Index(name = "email_index", columnList = "email")
    })
public class Account {

    @Id
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

    @ManyToMany(
        fetch = FetchType.EAGER,
        cascade = CascadeType.MERGE)
    @JoinTable(
        name = "accounts_to_roles",
        joinColumns = @JoinColumn (name = "account_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;

    protected Account() {}
    public Account(
        String username,
        String password,
        String email,
        String secretWord,
        Set<Role> roles
    ) {
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

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
