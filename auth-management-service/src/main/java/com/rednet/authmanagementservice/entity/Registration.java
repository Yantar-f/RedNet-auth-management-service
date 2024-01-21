package com.rednet.authmanagementservice.entity;

public class Registration {
    private String ID;
    private String activationCode;
    private String tokenID;
    private String username;
    private String email;
    private String encodedPassword;
    private String encodedSecretWord;

    public Registration(String ID,
                        String activationCode,
                        String tokenID,
                        String username,
                        String email,
                        String encodedPassword,
                        String encodedSecretWord) {
        this.ID = ID;
        this.activationCode = activationCode;
        this.tokenID = tokenID;
        this.username = username;
        this.email = email;
        this.encodedPassword = encodedPassword;
        this.encodedSecretWord = encodedSecretWord;
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

    public String getEncodedPassword() {
        return encodedPassword;
    }

    public void setEncodedPassword(String encodedPassword) {
        this.encodedPassword = encodedPassword;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEncodedSecretWord() {
        return encodedSecretWord;
    }

    public void setEncodedSecretWord(String encodedSecretWord) {
        this.encodedSecretWord = encodedSecretWord;
    }

    public String getID() {
        return ID;
    }

    public void setID(String ID) {
        this.ID = ID;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;

        Registration registration = (Registration) obj;

        return  ID.equals(registration.ID) &&
                activationCode.equals(registration.activationCode) &&
                tokenID.equals(registration.tokenID) &&
                username.equals(registration.username) &&
                email.equals(registration.email) &&
                encodedPassword.equals(registration.encodedPassword) &&
                encodedSecretWord.equals(registration.encodedSecretWord);
    }

    @Override
    public int hashCode() {
        return  ID.hashCode() *
                activationCode.hashCode() *
                tokenID.hashCode() *
                username.hashCode() *
                email.hashCode() *
                encodedPassword.hashCode() *
                encodedSecretWord.hashCode();
    }
}
