package com.rednet.authmanagementservice.entity;

public class Registration {
    private String activationCode;
    private String username;
    private String password;
    private String email;
    private String secretWord;

    public Registration(
        String activationCode,
        String username,
        String password,
        String email,
        String secretWord
    ) {
        this.activationCode = activationCode;
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
