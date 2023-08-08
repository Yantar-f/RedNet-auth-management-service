package com.rednet.authmanagementservice.payload;

public class SignupRequestMessage {
    private String username;
    private String email;
    private String password;
    private String secretWord;

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public String getSecretWord() {
        return secretWord;
    }
}
