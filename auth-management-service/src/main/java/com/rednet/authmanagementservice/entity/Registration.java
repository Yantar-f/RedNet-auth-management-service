package com.rednet.authmanagementservice.entity;


import java.io.Serializable;

public class Registration implements Serializable {
    private String activationCode;
    private String tokenID;
    private String username;
    private String password;
    private String email;
    private String secretWord;

    public Registration() {}
    public Registration(
        String activationCode,
        String tokenID, String username,
        String password,
        String email,
        String secretWord
    ) {
        this.activationCode = activationCode;
        this.tokenID = tokenID;
        this.username = username;
        this.password = password;
        this.email = email;
        this.secretWord = secretWord;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSecretWord() {
        return secretWord;
    }

    public void setSecretWord(String secretWord) {
        this.secretWord = secretWord;
    }
}
